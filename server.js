const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");
const {
  randomBytes,
  scryptSync,
  timingSafeEqual,
} = require("node:crypto");
const { DatabaseSync } = require("node:sqlite");

const ROOT = __dirname;
loadEnvFile();
const PORT = Number(process.env.PORT || 3000);
const DATA_DIR = path.join(ROOT, "data");
const DATABASE_PATH = process.env.DATABASE_PATH || path.join(DATA_DIR, "travlish.sqlite");
const UPLOAD_DIR = process.env.UPLOAD_DIR || path.join(DATA_DIR, "uploads");
const SESSION_DAYS = 7;
const MAX_BODY_BYTES = 32 * 1024;
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

fs.mkdirSync(path.dirname(DATABASE_PATH), { recursive: true });

const db = new DatabaseSync(DATABASE_PATH);
db.exec(`
  PRAGMA journal_mode = WAL;
  PRAGMA foreign_keys = ON;
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT NOT NULL COLLATE NOCASE UNIQUE,
    role TEXT NOT NULL CHECK (role IN ('admin', 'client')),
    password_salt TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS bookings (
    id INTEGER PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    car TEXT NOT NULL,
    customer TEXT NOT NULL,
    phone TEXT NOT NULL,
    email TEXT,
    pickup_date TEXT NOT NULL,
    handover TEXT NOT NULL,
    pickup TEXT NOT NULL,
    destination TEXT NOT NULL,
    duration TEXT,
    notes TEXT,
    status TEXT NOT NULL DEFAULT 'pending'
      CHECK (status IN ('pending', 'submitted', 'approved', 'rejected', 'documents_required', 'documents_submitted', 'under_review', 'verified', 'verification_failed', 'confirmed', 'completed', 'cancelled')),
    approved_by INTEGER REFERENCES users(id),
    approved_at TEXT,
    rejected_reason TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS document_verifications (
    id INTEGER PRIMARY KEY,
    booking_id INTEGER NOT NULL REFERENCES bookings(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    document_type TEXT NOT NULL CHECK (document_type IN ('aadhaar', 'pan', 'driver_license', 'passport', 'visa', 'other')),
    document_number TEXT NOT NULL,
    masked_number TEXT,
    document_name TEXT NOT NULL,
    file_path TEXT,
    file_name TEXT,
    file_mime TEXT,
    file_size INTEGER,
    status TEXT NOT NULL DEFAULT 'submitted' CHECK (status IN ('submitted', 'under_review', 'verified', 'rejected', 'reupload_requested')),
    verification_result TEXT,
    admin_notes TEXT,
    provider TEXT,
    provider_reference TEXT,
    verified_name TEXT,
    verified_by INTEGER REFERENCES users(id),
    submitted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    reviewed_at TEXT,
    verified_at TEXT,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS verification_logs (
    id INTEGER PRIMARY KEY,
    booking_id INTEGER NOT NULL REFERENCES bookings(id) ON DELETE CASCADE,
    verification_id INTEGER REFERENCES document_verifications(id) ON DELETE CASCADE,
    actor_role TEXT NOT NULL CHECK (actor_role IN ('admin', 'client')),
    actor_id INTEGER REFERENCES users(id),
    event TEXT NOT NULL,
    details TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE INDEX IF NOT EXISTS sessions_expiry_idx ON sessions(expires_at);
  CREATE INDEX IF NOT EXISTS bookings_created_idx ON bookings(created_at DESC);
  CREATE INDEX IF NOT EXISTS verification_booking_idx ON document_verifications(booking_id);
  CREATE INDEX IF NOT EXISTS verification_logs_booking_idx ON verification_logs(booking_id);
  CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    booking_id INTEGER REFERENCES bookings(id) ON DELETE CASCADE,
    document_id INTEGER REFERENCES document_verifications(id) ON DELETE CASCADE,
    type TEXT NOT NULL,
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    is_read INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS verification_attempts (
    id INTEGER PRIMARY KEY,
    booking_id INTEGER REFERENCES bookings(id) ON DELETE CASCADE,
    verification_id INTEGER REFERENCES document_verifications(id) ON DELETE CASCADE,
    document_type TEXT NOT NULL,
    masked_document_number TEXT,
    provider TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('success', 'failed', 'unavailable')),
    provider_reference TEXT,
    verified_name TEXT,
    details TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE INDEX IF NOT EXISTS notifications_user_idx ON notifications(user_id, created_at DESC);
`);

migrateSchema();
seedAdminFromEnvironment();

const statements = {
  createUser: db.prepare(
    "INSERT INTO users (name, email, role, password_salt, password_hash) VALUES (?, ?, ?, ?, ?)"
  ),
  findUser: db.prepare("SELECT * FROM users WHERE email = ?"),
  countAdmins: db.prepare("SELECT COUNT(*) AS count FROM users WHERE role = 'admin'"),
  createSession: db.prepare(
    "INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)"
  ),
  findSession: db.prepare(`
    SELECT users.id, users.name, users.email, users.role
    FROM sessions JOIN users ON users.id = sessions.user_id
    WHERE sessions.token = ? AND sessions.expires_at > ?
  `),
  deleteSession: db.prepare("DELETE FROM sessions WHERE token = ?"),
  createBooking: db.prepare(`
    INSERT INTO bookings
      (user_id, car, customer, phone, email, pickup_date, handover, pickup, destination, duration, notes)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `),
  listBookings: db.prepare(`
    SELECT id, user_id AS userId, car, customer, phone, email, pickup_date AS pickupDate,
      handover, pickup, destination, duration, notes, status, approved_by AS approvedBy,
      approved_at AS approvedAt, rejected_reason AS rejectedReason, created_at AS createdAt, updated_at AS updatedAt
    FROM bookings ORDER BY created_at DESC, id DESC LIMIT 500
  `),
  getBooking: db.prepare("SELECT id, user_id AS userId, status, approved_by AS approvedBy, approved_at AS approvedAt FROM bookings WHERE id = ?"),
  setBookingStatus: db.prepare("UPDATE bookings SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?"),
  insertVerification: db.prepare(`
    INSERT INTO document_verifications
      (booking_id, user_id, document_type, document_number, masked_number, document_name, file_path, file_name, file_mime, file_size, status)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `),
  listVerificationsForBooking: db.prepare(`
    SELECT id, booking_id AS bookingId, user_id AS userId, document_type AS documentType,
      document_number AS documentNumber, masked_number AS maskedNumber, document_name AS documentName,
      file_name AS fileName, file_mime AS fileMime, file_size AS fileSize, status, verification_result AS verificationResult,
      admin_notes AS adminNotes, provider, provider_reference AS providerReference, verified_name AS verifiedName,
      verified_by AS verifiedBy, submitted_at AS submittedAt, reviewed_at AS reviewedAt, verified_at AS verifiedAt
    FROM document_verifications WHERE booking_id = ? ORDER BY submitted_at DESC, id DESC
  `),
  createVerificationLog: db.prepare(`
    INSERT INTO verification_logs (booking_id, verification_id, actor_role, actor_id, event, details)
    VALUES (?, ?, ?, ?, ?, ?)
  `),
  listBookingLogs: db.prepare(`
    SELECT booking_id AS bookingId, verification_id AS verificationId, actor_role AS actorRole, actor_id AS actorId,
      event, details, created_at AS createdAt
    FROM verification_logs WHERE booking_id = ? ORDER BY created_at DESC, id DESC LIMIT 200
  `),
  getVerification: db.prepare(`
    SELECT id, booking_id AS bookingId, user_id AS userId, document_type AS documentType,
      document_number AS documentNumber, masked_number AS maskedNumber, document_name AS documentName,
      file_path AS filePath, file_name AS fileName, file_mime AS fileMime, file_size AS fileSize, status,
      verification_result AS verificationResult, admin_notes AS adminNotes, provider, provider_reference AS providerReference,
      verified_name AS verifiedName, verified_by AS verifiedBy, submitted_at AS submittedAt, reviewed_at AS reviewedAt,
      verified_at AS verifiedAt
    FROM document_verifications WHERE id = ?
  `),
  listAllVerifications: db.prepare(`
    SELECT v.id, v.booking_id AS bookingId, b.car, u.name AS customerName, u.email AS customerEmail,
      v.document_type AS documentType, v.document_number AS documentNumber, v.masked_number AS maskedNumber,
      v.document_name AS documentName, v.file_name AS fileName, v.status, v.verification_result AS verificationResult,
      v.admin_notes AS adminNotes, v.provider, v.provider_reference AS providerReference, v.verified_name AS verifiedName,
      v.submitted_at AS submittedAt, v.reviewed_at AS reviewedAt, v.verified_at AS verifiedAt
    FROM document_verifications v
    JOIN bookings b ON b.id = v.booking_id
    JOIN users u ON u.id = v.user_id
    ORDER BY v.submitted_at DESC, v.id DESC LIMIT 500
  `),
  updateVerification: db.prepare(`
    UPDATE document_verifications
    SET status = ?, verification_result = ?, admin_notes = ?, verified_by = ?, reviewed_at = ?, verified_at = ?, provider = ?, provider_reference = ?, verified_name = ?, updated_at = CURRENT_TIMESTAMP
    WHERE id = ?
  `),
  createNotification: db.prepare(`
    INSERT INTO notifications (user_id, booking_id, document_id, type, title, message)
    VALUES (?, ?, ?, ?, ?, ?)
  `),
  listNotifications: db.prepare(`
    SELECT id, user_id AS userId, booking_id AS bookingId, document_id AS documentId, type, title, message,
      is_read AS isRead, created_at AS createdAt
    FROM notifications WHERE user_id = ? ORDER BY created_at DESC, id DESC LIMIT 100
  `),
  markNotificationRead: db.prepare("UPDATE notifications SET is_read = 1 WHERE id = ? AND user_id = ?"),
  createVerificationAttempt: db.prepare(`
    INSERT INTO verification_attempts (booking_id, verification_id, document_type, masked_document_number, provider, status, provider_reference, verified_name, details)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `),
  listVerificationAttempts: db.prepare(`
    SELECT id, booking_id AS bookingId, verification_id AS verificationId, document_type AS documentType,
      masked_document_number AS maskedDocumentNumber, provider, status, provider_reference AS providerReference,
      verified_name AS verifiedName, details, created_at AS createdAt
    FROM verification_attempts WHERE booking_id = ? ORDER BY created_at DESC, id DESC LIMIT 100
  `),
};

function tableColumns(table) {
  return db.prepare(`PRAGMA table_info(${table})`).all().map((column) => column.name);
}

function migrateSchema() {
  const bookingColumns = tableColumns("bookings");
  if (!bookingColumns.includes("approved_by")) {
    db.exec(`
      CREATE TABLE bookings_new (
        id INTEGER PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        car TEXT NOT NULL,
        customer TEXT NOT NULL,
        phone TEXT NOT NULL,
        email TEXT,
        pickup_date TEXT NOT NULL,
        handover TEXT NOT NULL,
        pickup TEXT NOT NULL,
        destination TEXT NOT NULL,
        duration TEXT,
        notes TEXT,
        status TEXT NOT NULL DEFAULT 'pending'
          CHECK (status IN ('pending', 'submitted', 'approved', 'rejected', 'documents_required', 'documents_submitted', 'under_review', 'verified', 'verification_failed', 'confirmed', 'completed', 'cancelled')),
        approved_by INTEGER REFERENCES users(id),
        approved_at TEXT,
        rejected_reason TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      );
      INSERT INTO bookings_new (id, user_id, car, customer, phone, email, pickup_date, handover, pickup, destination, duration, notes, status, created_at)
        SELECT id, user_id, car, customer, phone, email, pickup_date, handover, pickup, destination, duration, notes, status, created_at FROM bookings;
      DROP TABLE bookings;
      ALTER TABLE bookings_new RENAME TO bookings;
    `);
    db.exec("CREATE INDEX IF NOT EXISTS bookings_created_idx ON bookings(created_at DESC);");
  }

  const documentColumns = tableColumns("document_verifications");
  if (!documentColumns.includes("file_path")) {
    db.exec(`
      CREATE TABLE document_verifications_new (
        id INTEGER PRIMARY KEY,
        booking_id INTEGER NOT NULL REFERENCES bookings(id) ON DELETE CASCADE,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        document_type TEXT NOT NULL CHECK (document_type IN ('aadhaar', 'pan', 'driver_license', 'passport', 'visa', 'other')),
        document_number TEXT NOT NULL,
        masked_number TEXT,
        document_name TEXT NOT NULL,
        file_path TEXT,
        file_name TEXT,
        file_mime TEXT,
        file_size INTEGER,
        status TEXT NOT NULL DEFAULT 'submitted' CHECK (status IN ('submitted', 'under_review', 'verified', 'rejected', 'reupload_requested')),
        verification_result TEXT,
        admin_notes TEXT,
        provider TEXT,
        provider_reference TEXT,
        verified_name TEXT,
        verified_by INTEGER REFERENCES users(id),
        submitted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        reviewed_at TEXT,
        verified_at TEXT,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      );
      INSERT INTO document_verifications_new (id, booking_id, user_id, document_type, document_number, document_name, status, verification_result, verified_by, submitted_at, reviewed_at)
        SELECT id, booking_id, user_id, document_type, document_number, document_name, status, verification_result, verified_by, submitted_at, reviewed_at FROM document_verifications;
      DROP TABLE document_verifications;
      ALTER TABLE document_verifications_new RENAME TO document_verifications;
    `);
    db.exec("CREATE INDEX IF NOT EXISTS verification_booking_idx ON document_verifications(booking_id);");
  }

  db.exec(`
    CREATE TABLE IF NOT EXISTS notifications (
      id INTEGER PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      booking_id INTEGER REFERENCES bookings(id) ON DELETE CASCADE,
      document_id INTEGER REFERENCES document_verifications(id) ON DELETE CASCADE,
      type TEXT NOT NULL,
      title TEXT NOT NULL,
      message TEXT NOT NULL,
      is_read INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS verification_attempts (
      id INTEGER PRIMARY KEY,
      booking_id INTEGER REFERENCES bookings(id) ON DELETE CASCADE,
      verification_id INTEGER REFERENCES document_verifications(id) ON DELETE CASCADE,
      document_type TEXT NOT NULL,
      masked_document_number TEXT,
      provider TEXT NOT NULL,
      status TEXT NOT NULL CHECK (status IN ('success', 'failed', 'unavailable')),
      provider_reference TEXT,
      verified_name TEXT,
      details TEXT,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE INDEX IF NOT EXISTS notifications_user_idx ON notifications(user_id, created_at DESC);
  `);
}

const sessionsCookie = "travlish_session";
const loginAttempts = new Map();

const server = http.createServer(async (request, response) => {
  setSecurityHeaders(response);

  try {
    const url = new URL(request.url, `http://${request.headers.host || "localhost"}`);
    const pathname = decodeURIComponent(url.pathname);

    if (request.method === "GET" && pathname === "/api/config") {
      const adminExists = statements.countAdmins.get().count > 0;
      return sendJson(response, 200, {
        adminRegistrationOpen: !adminExists && Boolean(process.env.ADMIN_SETUP_TOKEN),
        googleAuthEnabled: false,
      });
    }

    function getContentType(filePath) {
      const types = {
        ".html": "text/html; charset=utf-8",
        ".css": "text/css; charset=utf-8",
        ".js": "text/javascript; charset=utf-8",
        ".jpeg": "image/jpeg",
        ".jpg": "image/jpeg",
        ".png": "image/png",
        ".webp": "image/webp",
        ".svg": "image/svg+xml",
      };
      return types[path.extname(filePath).toLowerCase()] || "application/octet-stream";
    }

    if (request.method === "POST" && pathname === "/api/bookings") {
      return await createBooking(request, response);
    }

    if (request.method === "POST" && pathname === "/api/admin/bookings/status") {
      const user = requireAdmin(request, response);
      if (!user) return;
      return await updateBookingStatus(request, response);
    }

    if (request.method === "GET" && pathname === "/api/admin/dashboard") {
      if (!requireAdmin(request, response)) return;
      return sendJson(response, 200, getDashboardData());
    }

    if (request.method === "GET" && pathname === "/api/client/dashboard") {
      if (!requireClient(request, response)) return;
      return sendJson(response, 200, getClientDashboardData(getSessionUser(request)));
    }

    if (request.method === "GET" && pathname === "/Client/dashboard.html") {
      const user = getSessionUser(request);
      if (!user || user.role !== "client") {
        response.writeHead(302, { Location: "/Client/login.html?error=Please%20sign%20in%20to%20access%20your%20dashboard." });
        return response.end();
      }
    }

    if (request.method === "GET" && pathname === "/api/admin/document-verifications") {
      if (!requireAdmin(request, response)) return;
      return sendJson(response, 200, getAdminVerificationData());
    }

    if (request.method === "POST" && pathname === "/api/client/document-verification") {
      const user = requireClient(request, response);
      if (!user) return;
      return await submitClientVerification(request, response, user);
    }

    if (request.method === "GET" && pathname === "/api/client/notifications") {
      const user = requireClient(request, response);
      if (!user) return;
      return sendJson(response, 200, { items: statements.listNotifications.all(user.id) });
    }

    if (request.method === "POST" && pathname.startsWith("/api/client/notifications/") && pathname.endsWith("/read")) {
      const user = requireClient(request, response);
      if (!user) return;
      const id = Number(pathname.split("/")[4]);
      if (!Number.isSafeInteger(id) || id < 1) return sendJson(response, 400, { error: "Invalid notification id." });
      statements.markNotificationRead.run(id, user.id);
      return sendJson(response, 200, { id, read: true });
    }

    if (request.method === "POST" && pathname === "/api/admin/document-verification-tool") {
      if (!requireAdmin(request, response)) return;
      return await runDocumentVerificationTool(request, response);
    }

    if (request.method === "GET" && pathname.startsWith("/api/documents/") && pathname.endsWith("/file")) {
      const user = getSessionUser(request);
      if (!user) return sendJson(response, 401, { error: "Sign-in is required." });
      const id = Number(pathname.split("/")[3]);
      if (!Number.isSafeInteger(id) || id < 1) return sendJson(response, 400, { error: "Invalid document id." });
      return await serveDocumentFile(request, response, user, id);
    }

    if (request.method === "POST" && pathname.startsWith("/api/admin/document-verifications/")) {
      if (!requireAdmin(request, response)) return;
      return await verifyDocumentSubmission(request, response);
    }

    if (request.method === "GET" && pathname === "/api/me") {
      const user = getSessionUser(request);
      return sendJson(response, 200, {
        user: user ? { name: user.name, email: user.email, role: user.role } : null,
      });
    }

    if (request.method === "POST" && pathname === "/auth/logout") {
      return logout(request, response);
    }

    if (request.method === "GET" && pathname.endsWith("/auth/google")) {
      const loginPath = pathname.startsWith("/admin/") ? "/Admin/login.html" : "/Client/login.html";
      return sendHtml(response, 501, pageMessage(
        "Google sign-in is not configured",
        "Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in your environment before enabling Google sign-in.",
        loginPath
      ));
    }

    if (request.method === "GET" && pathname.endsWith("/auth/forgot-password")) {
      const loginPath = pathname.startsWith("/admin/") ? "/Admin/login.html" : "/Client/login.html";
      return sendHtml(response, 501, pageMessage(
        "Password reset is unavailable",
        "No email delivery service is configured for this project. Contact the site administrator to reset your password.",
        loginPath
      ));
    }

    if (request.method === "POST" && pathname === "/admin/auth/register") {
      return await registerAdmin(request, response);
    }

    if (request.method === "POST" && pathname === "/client/auth/register") {
      return await registerClient(request, response);
    }

    if (request.method === "POST" && (pathname === "/admin/auth/login" || pathname === "/client/auth/login")) {
      return await login(request, response, pathname.startsWith("/admin/") ? "admin" : "client");
    }

    if (request.method === "POST" && pathname === "/auth/password-reset") {
      return sendHtml(response, 501, pageMessage(
        "Password reset is unavailable",
        "No email delivery service is configured for this project. Contact the site administrator to reset your password.",
        "/Client/login.html"
      ));
    }

    if (request.method !== "GET" && request.method !== "HEAD") {
      return sendJson(response, 404, { error: "Route not found." });
    }

    const filePath = resolvePublicFile(pathname);
    if (!filePath) return sendJson(response, 404, { error: "Page not found." });

    if (filePath.endsWith(path.join("Admin", "dashboard.html"))) {
      const user = getSessionUser(request);
      if (!user || user.role !== "admin") {
        response.writeHead(302, { Location: "/Admin/login.html?error=Please%20sign%20in%20as%20an%20administrator." });
        return response.end();
      }
    }
    if (filePath.endsWith(path.join("Client", "dashboard.html"))) {
      const user = getSessionUser(request);
      if (!user || user.role !== "client") {
        response.writeHead(302, { Location: "/Client/login.html?error=Please%20sign%20in%20as%20a%20client." });
        return response.end();
      }
    }

    const contentType = getContentType(filePath);
    response.writeHead(200, { "Content-Type": contentType });
    if (request.method === "HEAD") return response.end();
    return fs.createReadStream(filePath).pipe(response);
  } catch (error) {
    console.error("Request failed:", error);
    if (!response.headersSent) sendJson(response, error.statusCode || 500, { error: error.statusCode ? error.message : "An unexpected server error occurred." });
    else response.destroy(error);
  }
});

server.listen(PORT, () => {
  console.log(`Travlish is running at http://localhost:${PORT}`);
  console.log(`SQLite database: ${DATABASE_PATH}`);
});

function loadEnvFile() {
  const envPath = path.join(ROOT, ".env");
  if (!fs.existsSync(envPath)) return;

  for (const line of fs.readFileSync(envPath, "utf8").split(/\r?\n/)) {
    const match = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/);
    if (!match || Object.hasOwn(process.env, match[1])) continue;
    const value = match[2].replace(/^(['"])(.*)\1$/, "$2");
    process.env[match[1]] = value;
  }
}

function seedAdminFromEnvironment() {
  const email = process.env.ADMIN_EMAIL?.trim().toLowerCase();
  const password = process.env.ADMIN_PASSWORD;
  if (!email && !password) return;
  if (!email || !password || !EMAIL_PATTERN.test(email) || password.length < 12) {
    throw new Error("Set both ADMIN_EMAIL and ADMIN_PASSWORD; the password must be at least 12 characters.");
  }

  const existing = db.prepare("SELECT id FROM users WHERE email = ?").get(email);
  if (existing) return;
  const { salt, hash } = hashPassword(password);
  statementsCreateUser("Admin", email, "admin", salt, hash);
  console.log(`Created initial admin account for ${email}.`);
}

function statementsCreateUser(name, email, role, salt, hash) {
  db.prepare(
    "INSERT INTO users (name, email, role, password_salt, password_hash) VALUES (?, ?, ?, ?, ?)"
  ).run(name, email, role, salt, hash);
}

function hashPassword(password, salt = randomBytes(16).toString("hex")) {
  const hash = scryptSync(password, salt, 64).toString("hex");
  return { salt, hash };
}

function passwordMatches(password, salt, expectedHash) {
  const actual = Buffer.from(hashPassword(password, salt).hash, "hex");
  const expected = Buffer.from(expectedHash, "hex");
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

function createSession(response, userId, remember = false) {
  const token = randomBytes(32).toString("hex");
  const duration = remember ? SESSION_DAYS * 24 * 60 * 60 : 12 * 60 * 60;
  statements.createSession.run(token, userId, Date.now() + duration * 1000);
  const secure = process.env.COOKIE_SECURE === "true" ? "; Secure" : "";
  const maxAge = remember ? `; Max-Age=${duration}` : "";
  response.setHeader("Set-Cookie", `${sessionsCookie}=${token}; HttpOnly; SameSite=Lax; Path=/${maxAge}${secure}`);
}

function getSessionUser(request) {
  const token = parseCookies(request.headers.cookie)[sessionsCookie];
  return token ? statements.findSession.get(token, Date.now()) || null : null;
}

function requireAdmin(request, response) {
  const user = getSessionUser(request);
  if (!user || user.role !== "admin") {
    sendJson(response, 401, { error: "Administrator sign-in is required." });
    return null;
  }
  return user;
}

function requireClient(request, response) {
  const user = getSessionUser(request);
  if (!user || user.role !== "client") {
    sendJson(response, 401, { error: "Client sign-in is required." });
    return null;
  }
  return user;
}

function parseCookies(header = "") {
  return Object.fromEntries(header.split(";").map(part => {
    const index = part.indexOf("=");
    return index < 0 ? ["", ""] : [part.slice(0, index).trim(), decodeURIComponent(part.slice(index + 1).trim())];
  }).filter(([key]) => key));
}

async function readBody(request) {
  const chunks = [];
  let bytes = 0;
  for await (const chunk of request) {
    bytes += chunk.length;
    if (bytes > MAX_BODY_BYTES) throw Object.assign(new Error("Request body is too large."), { statusCode: 413 });
    chunks.push(chunk);
  }

  const raw = Buffer.concat(chunks).toString("utf8");
  const contentType = request.headers["content-type"] || "";
  if (contentType.includes("application/json")) {
    try {
      const body = JSON.parse(raw);
      if (!body || typeof body !== "object" || Array.isArray(body)) throw new Error("Expected an object.");
      return body;
    } catch {
      throw Object.assign(new Error("Invalid JSON request body."), { statusCode: 400 });
    }
  }
  return Object.fromEntries(new URLSearchParams(raw));
}

async function readForm(request) {
  try {
    return await readBody(request);
  } catch (error) {
    throw Object.assign(error, { statusCode: error.statusCode || 400 });
  }
}

function maskDocumentNumber(value) {
  const cleaned = String(value || "").replace(/\s+/g, "");
  if (cleaned.length <= 4) return cleaned;
  return `${"*".repeat(Math.max(0, cleaned.length - 4))}${cleaned.slice(-4)}`;
}

async function parseMultipart(request) {
  const contentType = request.headers["content-type"] || "";
  const boundaryMatch = contentType.match(/boundary=(?:"([^"]+)"|([^;]+))/i);
  const boundary = boundaryMatch ? (boundaryMatch[1] || boundaryMatch[2] || "").trim() : "";
  if (!boundary) throw Object.assign(new Error("Multipart boundary is missing."), { statusCode: 400 });

  const chunks = [];
  let bytes = 0;
  for await (const chunk of request) {
    bytes += chunk.length;
    if (bytes > MAX_BODY_BYTES) throw Object.assign(new Error("Request body is too large."), { statusCode: 413 });
    chunks.push(chunk);
  }
  const buffer = Buffer.concat(chunks);
  const delimiter = Buffer.from(`--${boundary}`);
  const parts = [];
  let cursor = buffer.indexOf(delimiter);
  while (cursor !== -1) {
    const next = buffer.indexOf(delimiter, cursor + delimiter.length);
    if (next === -1) break;
    const part = buffer.slice(cursor + delimiter.length, next);
    const headerEnd = part.indexOf("\r\n\r\n");
    if (headerEnd !== -1) {
      const headerText = part.slice(0, headerEnd).toString("utf8");
      let content = part.slice(headerEnd + 4);
      if (content.length >= 2 && content[content.length - 2] === 0x0d && content[content.length - 1] === 0x0a) {
        content = content.slice(0, -2);
      }
      parts.push({ headerText, content });
    }
    cursor = next;
  }

  const fields = {};
  const files = [];
  for (const part of parts) {
    const nameMatch = part.headerText.match(/name="([^"]+)"/);
    if (!nameMatch) continue;
    const name = nameMatch[1];
    const filenameMatch = part.headerText.match(/filename="([^"]*)"/);
    if (filenameMatch && filenameMatch[1]) {
      const mimeMatch = part.headerText.match(/Content-Type:\s*([^\r\n]+)/i);
      files.push({
        fieldname: name,
        filename: filenameMatch[1],
        mimetype: mimeMatch ? mimeMatch[1].trim() : "application/octet-stream",
        data: part.content,
      });
    } else {
      fields[name] = part.content.toString("utf8");
    }
  }
  return { fields, files };
}

async function login(request, response, requiredRole) {
  const body = await readForm(request);
  const email = String(body.email || "").trim().toLowerCase();
  const password = String(body.password || "");
  const key = `${request.socket.remoteAddress}:${email}`;
  const attempt = loginAttempts.get(key) || { count: 0, until: 0 };

  if (attempt.until > Date.now()) {
    return authError(response, requiredRole, "Too many attempts. Try again in 15 minutes.");
  }
  const user = statements.findUser.get(email);
  if (!EMAIL_PATTERN.test(email) || !user || user.role !== requiredRole || !passwordMatches(password, user.password_salt, user.password_hash)) {
    attempt.count += 1;
    attempt.until = attempt.count >= 8 ? Date.now() + 15 * 60 * 1000 : 0;
    loginAttempts.set(key, attempt);
    return authError(response, requiredRole, "Email or password is incorrect.");
  }

  loginAttempts.delete(key);
  createSession(response, user.id, body.remember === "on" || body.remember === "1");
  response.writeHead(303, { Location: requiredRole === "admin" ? "/Admin/dashboard.html" : "/Client/dashboard.html" });
  response.end();
}

async function registerClient(request, response) {
  const body = await readForm(request);
  const result = validateAccount(body, true);
  if (result.error) return authError(response, "client", result.error, true);

  const { salt, hash } = hashPassword(result.password);
  try {
    const created = statements.createUser.run(result.name, result.email, "client", salt, hash);
    createSession(response, Number(created.lastInsertRowid), false);
    response.writeHead(303, { Location: "/Index.html?registered=1" });
    response.end();
  } catch (error) {
    if (String(error.message).includes("UNIQUE")) return authError(response, "client", "An account with this email already exists.", true);
    throw error;
  }
}

async function registerAdmin(request, response) {
  const body = await readForm(request);
  if (!process.env.ADMIN_SETUP_TOKEN || statements.countAdmins.get().count > 0) {
    return authError(response, "admin", "Administrator registration is closed.");
  }
  if (!safeSecretEqual(String(body.setupToken || ""), process.env.ADMIN_SETUP_TOKEN)) {
    return authError(response, "admin", "The administrator setup token is incorrect.", true);
  }

  const result = validateAccount(body, true);
  if (result.error) return authError(response, "admin", result.error, true);
  const { salt, hash } = hashPassword(result.password);
  try {
    const created = statements.createUser.run(result.name, result.email, "admin", salt, hash);
    createSession(response, Number(created.lastInsertRowid), false);
    response.writeHead(303, { Location: "/Admin/dashboard.html" });
    response.end();
  } catch (error) {
    if (String(error.message).includes("UNIQUE")) return authError(response, "admin", "An account with this email already exists.", true);
    throw error;
  }
}

function validateAccount(body, needsName) {
  const name = String(body.name || "").trim();
  const email = String(body.email || "").trim().toLowerCase();
  const password = String(body.password || "");
  if (needsName && (name.length < 2 || name.length > 120)) return { error: "Enter a name between 2 and 120 characters." };
  if (!EMAIL_PATTERN.test(email) || email.length > 254) return { error: "Enter a valid email address." };
  if (password.length < 8 || password.length > 256) return { error: "Password must be between 8 and 256 characters." };
  if (String(body.confirmPassword || "") !== password) return { error: "Passwords do not match." };
  return { name, email, password };
}

function safeSecretEqual(input, expected) {
  const actual = Buffer.from(input);
  const target = Buffer.from(expected);
  return actual.length === target.length && timingSafeEqual(actual, target);
}

async function createBooking(request, response) {
  const body = await readBody(request);
  const user = getSessionUser(request);
  const fields = {
    car: body.car,
    customer: body.customer,
    phone: body.phone,
    email: body.email,
    pickupDate: body.pickupDate,
    handover: body.handover,
    pickup: body.pickup,
    destination: body.destination,
    duration: body.duration,
    notes: body.notes,
  };
  const limits = { car: 120, customer: 120, phone: 40, email: 254, handover: 160, pickup: 300, destination: 300, duration: 200, notes: 2000 };
  for (const [field, limit] of Object.entries(limits)) {
    if (String(fields[field] || "").length > limit) return sendJson(response, 400, { error: `${field} is too long.` });
  }
  for (const field of ["car", "customer", "phone", "pickupDate", "handover", "pickup", "destination"]) {
    if (!String(fields[field] || "").trim()) return sendJson(response, 400, { error: `Please provide ${field}.` });
  }
  const parsedPickupDate = new Date(`${fields.pickupDate}T00:00:00Z`);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(String(fields.pickupDate))
    || Number.isNaN(parsedPickupDate.getTime())
    || parsedPickupDate.toISOString().slice(0, 10) !== fields.pickupDate
    || fields.pickupDate < new Date().toISOString().slice(0, 10)) {
    return sendJson(response, 400, { error: "Choose a valid pickup date." });
  }
  if (!["At my doorstep — deliver the car to my location", "I'll collect and return the car myself"].includes(fields.handover)) {
    return sendJson(response, 400, { error: "Choose a valid handover option." });
  }
  if (fields.email && !EMAIL_PATTERN.test(String(fields.email))) return sendJson(response, 400, { error: "Enter a valid email address." });
  if (String(fields.phone).replace(/\D/g, "").length < 7) return sendJson(response, 400, { error: "Enter a valid phone number." });

  if (!user || user.role !== "client") {
    return sendJson(response, 401, { error: "Please log in as a client before submitting a booking request." });
  }

  const inserted = statements.createBooking.run(
    user.id,
    String(fields.car).trim(),
    String(fields.customer).trim(),
    String(fields.phone).trim(),
    fields.email ? String(fields.email).trim().toLowerCase() : null,
    String(fields.pickupDate),
    String(fields.handover).trim(),
    String(fields.pickup).trim(),
    String(fields.destination).trim(),
    String(fields.duration || "").trim(),
    String(fields.notes || "").trim()
  );
  const bookingId = Number(inserted.lastInsertRowid);
  statements.createVerificationLog.run(bookingId, null, "client", user.id, "booking_submitted", `Booking request created for ${String(fields.car).trim()} by ${user.email}`);
  statements.createNotification.run(user.id, bookingId, null, "booking_submitted", "Booking submitted", "Your booking request has been submitted successfully.");
  return sendJson(response, 201, { id: bookingId, status: "pending" });
}

const ALLOWED_BOOKING_STATUSES = ["pending", "submitted", "approved", "rejected", "documents_required", "documents_submitted", "under_review", "verified", "verification_failed", "confirmed", "completed", "cancelled"];

async function updateBookingStatus(request, response) {
  const admin = requireAdmin(request, response);
  if (!admin) return;
  const body = await readBody(request);
  const id = Number(body.id);
  const status = String(body.status || "");
  const remark = String(body.remark || "");
  if (!Number.isSafeInteger(id) || id < 1) return sendJson(response, 400, { error: "Invalid booking id." });
  if (!ALLOWED_BOOKING_STATUSES.includes(status)) {
    return sendJson(response, 400, { error: "Choose a valid booking status." });
  }
  const booking = statements.getBooking.get(id);
  if (!booking) return sendJson(response, 404, { error: "Booking not found." });

  if (status === "approved") {
    db.prepare("UPDATE bookings SET status = ?, approved_by = ?, approved_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = ?").run(status, admin.id, id);
  } else if (status === "rejected") {
    db.prepare("UPDATE bookings SET status = ?, rejected_reason = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?").run(status, remark || null, id);
  } else {
    statements.setBookingStatus.run(status, id);
  }

  statements.createVerificationLog.run(id, null, "admin", admin.id, "booking_status_updated", `Booking status changed to ${status}${remark ? `: ${remark}` : ""}`);

  if (booking.userId) {
    if (status === "approved") {
      statements.createNotification.run(booking.userId, id, null, "booking_approved", "Booking approved", "Your booking request has been approved. Please submit your documents for verification.");
    } else if (status === "rejected") {
      statements.createNotification.run(booking.userId, id, null, "booking_rejected", "Booking rejected", remark || "Your booking request could not be approved.");
    }
  }

  return sendJson(response, 200, { id, status });
}

function getDashboardData() {
  const bookings = statements.listBookings.all();
  const monthlyBookings = db.prepare(`
    SELECT COUNT(*) AS count FROM bookings
    WHERE strftime('%Y-%m', created_at) = strftime('%Y-%m', 'now')
  `).get().count;
  const customers = db.prepare("SELECT COUNT(DISTINCT phone) AS count FROM bookings").get().count;
  const statusCounts = db.prepare(`
    SELECT status, COUNT(*) AS count FROM bookings GROUP BY status
  `).all();
  const verificationRows = db.prepare(`
    SELECT document_type AS documentType, COUNT(*) AS count FROM document_verifications GROUP BY document_type
  `).all();
  const pendingDocumentCount = db.prepare(`
    SELECT COUNT(*) AS count FROM document_verifications WHERE status IN ('submitted', 'under_review')
  `).get().count;
  const approvedBookings = db.prepare("SELECT COUNT(*) AS count FROM bookings WHERE status = 'approved'").get().count;
  const verifiedDocuments = db.prepare("SELECT COUNT(*) AS count FROM document_verifications WHERE status = 'verified'").get().count;
  const failedVerifications = db.prepare("SELECT COUNT(*) AS count FROM document_verifications WHERE status = 'rejected'").get().count;
  return {
    bookings,
    stats: {
      bookings: Number(monthlyBookings),
      revenue: 0,
      customers: Number(customers),
      fleet: 7,
      enquiries: Number(statusCounts.find(item => item.status === "pending")?.count || 0),
      approvedBookings: Number(approvedBookings),
      documentChecks: Number(pendingDocumentCount),
      verifiedDocuments: Number(verifiedDocuments),
      failedVerifications: Number(failedVerifications),
      documentTypes: verificationRows,
    },
  };
}

function getClientDashboardData(user) {
  const bookings = db.prepare(`
    SELECT id, car, customer, phone, email, pickup_date AS pickupDate,
      handover, pickup, destination, duration, notes, status, approved_by AS approvedBy,
      approved_at AS approvedAt, rejected_reason AS rejectedReason, created_at AS createdAt, updated_at AS updatedAt
    FROM bookings WHERE user_id = ? ORDER BY created_at DESC, id DESC LIMIT 100
  `).all(user.id);
  const documents = db.prepare(`
    SELECT id, booking_id AS bookingId, document_type AS documentType, document_number AS documentNumber,
      masked_number AS maskedNumber, document_name AS documentName, file_name AS fileName, status,
      verification_result AS verificationResult, admin_notes AS adminNotes, provider, provider_reference AS providerReference,
      verified_name AS verifiedName, submitted_at AS submittedAt, reviewed_at AS reviewedAt, verified_at AS verifiedAt
    FROM document_verifications WHERE user_id = ? ORDER BY submitted_at DESC, id DESC
  `).all(user.id);
  const notifications = statements.listNotifications.all(user.id);
  return { bookings, documents, notifications, user: { name: user.name, email: user.email, role: user.role } };
}

function getAdminVerificationData() {
  const rows = statements.listAllVerifications.all();
  const logs = db.prepare(`
    SELECT booking_id AS bookingId, verification_id AS verificationId, actor_role AS actorRole,
      event, details, created_at AS createdAt FROM verification_logs ORDER BY created_at DESC LIMIT 200
  `).all();
  return { rows, logs };
}

async function submitClientVerification(request, response, user) {
  const contentType = request.headers["content-type"] || "";
  let body = {};
  let uploadedFile = null;
  if (contentType.includes("multipart/form-data")) {
    const parsed = await parseMultipart(request);
    body = parsed.fields || {};
    uploadedFile = parsed.files && parsed.files.length ? parsed.files[0] : null;
  } else {
    body = await readBody(request);
  }

  const bookingId = Number(body.bookingId);
  const documentType = String(body.documentType || "");
  const documentNumber = String(body.documentNumber || "");
  const documentName = String(body.documentName || body.fileName || "");
  if (!Number.isSafeInteger(bookingId) || bookingId < 1) {
    return sendJson(response, 400, { error: "Invalid booking id." });
  }
  if (!['aadhaar', 'pan', 'driver_license', 'passport', 'visa', 'other'].includes(documentType)) {
    return sendJson(response, 400, { error: "Choose a supported document type." });
  }
  if (!documentNumber.trim()) {
    return sendJson(response, 400, { error: "Document number is required." });
  }

  const booking = db.prepare("SELECT id, user_id FROM bookings WHERE id = ?").get(bookingId);
  if (!booking || booking.user_id !== user.id) {
    return sendJson(response, 404, { error: "Booking not found for this account." });
  }

  let filePath = null;
  let fileName = null;
  let fileMime = null;
  let fileSize = null;
  if (uploadedFile) {
    const allowedMimes = ["application/pdf", "image/jpeg", "image/jpg", "image/png"];
    if (!allowedMimes.includes(String(uploadedFile.mimetype || "").toLowerCase())) {
      return sendJson(response, 400, { error: "Unsupported file type. Use PDF, JPG, JPEG, or PNG." });
    }
    if (uploadedFile.data.length > 5 * 1024 * 1024) {
      return sendJson(response, 400, { error: "File is too large. Maximum size is 5 MB." });
    }
    fs.mkdirSync(UPLOAD_DIR, { recursive: true });
    const safeName = `${randomBytes(16).toString("hex")}${path.extname(uploadedFile.filename || "")}`;
    filePath = path.join(UPLOAD_DIR, safeName);
    fs.writeFileSync(filePath, uploadedFile.data);
    fileName = uploadedFile.filename || safeName;
    fileMime = uploadedFile.mimetype;
    fileSize = uploadedFile.data.length;
  }

  const masked = maskDocumentNumber(documentNumber.trim());
  const finalName = documentName.trim() || fileName || "Document";
  const submitted = statements.insertVerification.run(
    bookingId,
    user.id,
    documentType,
    documentNumber.trim(),
    masked,
    finalName,
    filePath,
    fileName,
    fileMime,
    fileSize,
    "submitted"
  );
  const verificationId = Number(submitted.lastInsertRowid);
  statements.createVerificationLog.run(bookingId, verificationId, "client", user.id, "document_submitted", `Submitted ${documentType} document for verification`);
  statements.createNotification.run(user.id, bookingId, verificationId, "document_submitted", "Document submitted", "Your document has been submitted and is under review.");

  // Notify admins
  const admins = db.prepare("SELECT id FROM users WHERE role = 'admin'").all();
  for (const admin of admins) {
    statements.createNotification.run(admin.id, bookingId, verificationId, "document_submitted_admin", "New document submitted", `A new ${documentType} document was submitted for booking #${bookingId}.`);
  }

  return sendJson(response, 201, { id: verificationId, status: "submitted" });
}

async function verifyDocumentSubmission(request, response) {
  const admin = requireAdmin(request, response);
  if (!admin) return;
  const body = await readBody(request);
  const verificationId = Number(body.verificationId);
  const bookingId = Number(body.bookingId);
  const status = String(body.status || "");
  const remark = String(body.remark || "");
  const verifiedName = String(body.verifiedName || "").trim() || null;
  const providerReference = String(body.providerReference || "").trim() || null;
  const provider = String(body.provider || "").trim() || null;
  if (!Number.isSafeInteger(verificationId) || verificationId < 1) {
    return sendJson(response, 400, { error: "Invalid verification id." });
  }
  if (!['submitted', 'under_review', 'verified', 'rejected', 'reupload_requested'].includes(status)) {
    return sendJson(response, 400, { error: "Choose a valid verification status." });
  }
  const verification = statements.getVerification.get(verificationId);
  if (!verification || Number(verification.bookingId) !== bookingId) {
    return sendJson(response, 404, { error: "Verification record not found." });
  }

  const reviewedAt = new Date().toISOString();
  const verifiedAt = status === "verified" ? reviewedAt : null;
  statements.updateVerification.run(
    status,
    remark || null,
    remark || null,
    admin.id,
    reviewedAt,
    verifiedAt,
    provider,
    providerReference,
    verifiedName,
    verificationId
  );

  statements.createVerificationLog.run(bookingId, verificationId, "admin", admin.id, `document_${status}`, remark || 'No review note provided');

  // Update booking status sensibly
  if (status === "verified") {
    db.prepare("UPDATE bookings SET status = 'verified', updated_at = CURRENT_TIMESTAMP WHERE id = ?").run(bookingId);
  } else if (status === "reupload_requested" || status === "rejected") {
    db.prepare("UPDATE bookings SET status = 'documents_required', updated_at = CURRENT_TIMESTAMP WHERE id = ?").run(bookingId);
  }

  if (verification.userId) {
    let message = "Your document is under review.";
    let title = "Document update";
    if (status === "verified") { title = "Document verified"; message = "Your document has been successfully verified."; }
    else if (status === "rejected") { title = "Document rejected"; message = remark || "Your document could not be verified. Please review the admin's instructions and submit again."; }
    else if (status === "reupload_requested") { title = "Re-upload requested"; message = remark || "Please re-upload your document because additional verification is required."; }
    else if (status === "under_review") { title = "Document under review"; message = "Your document has been submitted and is under review."; }
    statements.createNotification.run(verification.userId, bookingId, verificationId, `document_${status}`, title, message);
  }

  return sendJson(response, 200, { id: verificationId, bookingId, status });
}

async function runDocumentVerificationTool(request, response) {
  const body = await readBody(request);
  const documentType = String(body.documentType || "");
  const documentNumber = String(body.documentNumber || "");
  if (!['aadhaar', 'pan', 'driver_license', 'passport', 'visa', 'other'].includes(documentType)) {
    return sendJson(response, 400, { error: "Choose a supported document type." });
  }
  if (!documentNumber.trim()) {
    return sendJson(response, 400, { error: "Document number is required." });
  }
  const result = await verifyDocumentWithProvider({ documentType, documentNumber: documentNumber.trim() });
  statements.createVerificationAttempt.run(null, null, documentType, maskDocumentNumber(documentNumber.trim()), result.provider, result.status, result.reference || null, result.verifiedName || null, result.message || result.details || null);
  return sendJson(response, 200, result);
}

async function verifyDocumentWithProvider({ documentType, documentNumber }) {
  const providerName = String(process.env.DOCUMENT_VERIFICATION_PROVIDER || "none").trim().toLowerCase();
  if (!providerName || providerName === "none" || providerName === "manual") {
    return {
      provider: providerName || "none",
      status: "unavailable",
      message: "No legitimate verification provider is configured. Use manual verification workflow.",
      reference: null,
      verifiedName: null,
      details: "Configure DOCUMENT_VERIFICATION_PROVIDER and related credentials to enable automated verification.",
    };
  }

  if (providerName === "http") {
    const url = process.env.DOCUMENT_VERIFICATION_API_URL;
    const apiKey = process.env.DOCUMENT_VERIFICATION_API_KEY;
    if (!url) {
      return {
        provider: "http",
        status: "unavailable",
        message: "Verification provider is not configured.",
        reference: null,
        verifiedName: null,
        details: "Set DOCUMENT_VERIFICATION_API_URL.",
      };
    }
    try {
      const res = await fetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(apiKey ? { Authorization: `Bearer ${apiKey}` } : {}),
        },
        body: JSON.stringify({ documentType, documentNumber }),
      });
      if (!res.ok) {
        return {
          provider: "http",
          status: "failed",
          message: "Verification could not be completed.",
          reference: null,
          verifiedName: null,
          details: `Provider returned HTTP ${res.status}.`,
        };
      }
      const data = await res.json().catch(() => ({}));
      const verified = Boolean(data.verified || data.success || data.status === "verified");
      return {
        provider: "http",
        status: verified ? "success" : "failed",
        message: verified ? "Document verified successfully." : (data.message || "Verification failed."),
        reference: data.reference || data.id || null,
        verifiedName: data.name || data.verifiedName || null,
        details: data.details || data.message || null,
      };
    } catch (error) {
      return {
        provider: "http",
        status: "unavailable",
        message: "Verification provider is unavailable.",
        reference: null,
        verifiedName: null,
        details: "The verification request could not be completed.",
      };
    }
  }

  return {
    provider: providerName,
    status: "unavailable",
    message: "Unsupported verification provider configuration.",
    reference: null,
    verifiedName: null,
    details: "Use a supported provider or manual verification.",
  };
}

async function serveDocumentFile(request, response, user, id) {
  const verification = statements.getVerification.get(id);
  if (!verification || !verification.filePath) {
    return sendJson(response, 404, { error: "Document file not found." });
  }
  if (user.role !== "admin" && Number(verification.userId) !== user.id) {
    return sendJson(response, 403, { error: "You are not authorized to view this document." });
  }
  if (!fs.existsSync(verification.filePath)) {
    return sendJson(response, 404, { error: "Document file not found." });
  }
  const stat = fs.statSync(verification.filePath);
  const mime = verification.fileMime || "application/octet-stream";
  response.writeHead(200, {
    "Content-Type": mime,
    "Content-Length": stat.size,
    "Content-Disposition": `inline; filename="${String(verification.fileName || "document").replace(/"/g, "")}"`,
  });
  fs.createReadStream(verification.filePath).pipe(response);
}

async function logout(request, response) {
  const token = parseCookies(request.headers.cookie)[sessionsCookie];
  const user = token ? statements.findSession.get(token, Date.now()) : null;
  if (token) statements.deleteSession.run(token);
  const redirect = user && user.role === "client" ? "/Client/login.html" : "/Admin/login.html";
  response.writeHead(303, {
    "Set-Cookie": `${sessionsCookie}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0`,
    Location: redirect,
  });
  response.end();
}

function authError(response, role, message, signup = false) {
  const page = role === "admin" ? "/Admin/login.html" : "/Client/login.html";
  const query = new URLSearchParams({ error: message, ...(signup ? { mode: "signup" } : {}) });
  response.writeHead(303, { Location: `${page}?${query.toString()}` });
  response.end();
}

function resolvePublicFile(pathname) {
  const normalized = pathname === "/" ? "/Index.html" : pathname;
  const allowed = new Map([
    ["/Index.html", path.join(ROOT, "Index.html")],
    ["/index.html", path.join(ROOT, "Index.html")],
    ["/Admin/login.html", path.join(ROOT, "Admin", "login.html")],
    ["/Admin/dashboard.html", path.join(ROOT, "Admin", "dashboard.html")],
    ["/Client/login.html", path.join(ROOT, "Client", "login.html")],
    ["/Client/dashboard.html", path.join(ROOT, "Client", "dashboard.html")],
  ]);
  const exact = allowed.get(normalized);
  if (exact && fs.existsSync(exact) && fs.statSync(exact).isFile()) return exact;
  if (!normalized.startsWith("/Assets/")) return null;
  const assetPath = path.resolve(ROOT, `.${normalized}`);
  if (!assetPath.startsWith(path.resolve(ROOT, "Assets") + path.sep)) return null;
  return fs.existsSync(assetPath) && fs.statSync(assetPath).isFile() ? assetPath : null;
}

function setSecurityHeaders(response) {
  response.setHeader("X-Content-Type-Options", "nosniff");
  response.setHeader("X-Frame-Options", "DENY");
  response.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  response.setHeader("Cache-Control", "no-store");
}

function sendJson(response, statusCode, body) {
  response.writeHead(statusCode, { "Content-Type": "application/json; charset=utf-8" });
  response.end(JSON.stringify(body));
}

function sendHtml(response, statusCode, body) {
  response.writeHead(statusCode, { "Content-Type": "text/html; charset=utf-8" });
  response.end(body);
}

function pageMessage(title, message, backLink) {
  return `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${escapeHtml(title)} - Travlish</title><body style="font:16px system-ui;background:#0c0d0f;color:#f7f7f7;min-height:100vh;display:grid;place-items:center"><main style="max-width:540px;padding:32px;background:#15171a;border:1px solid #333;border-radius:20px"><h1 style="color:#ffad57">${escapeHtml(title)}</h1><p>${escapeHtml(message)}</p><p><a style="color:#ffad57" href="${escapeHtml(backLink)}">Return to sign in</a></p></main></body></html>`;
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, character => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[character]);
}

server.on("close", () => db.close());
