import { FormEvent, useEffect, useRef, useState } from "react";
import {
  Link,
  Navigate,
  Route,
  Routes,
  useLocation,
  useNavigate,
  useParams,
} from "react-router-dom";
import { api } from "./api/client";
import { Role, useAuth, type User } from "./context/AuthContext";

type ErrorBody = { error?: { message?: string } };
type Document = {
  id: string;
  title: string;
  category: string;
  originalName: string;
  mimeType: string;
  sizeBytes: number;
  ownerId: string;
  ownerEmail: string;
  sha256: string;
  createdAt: string;
  accessLevel: "OWNER" | "SHARED";
  description?: string;
  scanVerdict?: string;
  updatedAt?: string;
};
type Permission = {
  id: string;
  granteeId: string;
  granteeEmail: string;
  granteeName: string;
  canView: boolean;
  canDownload: boolean;
  canReshare: boolean;
  grantedByEmail: string;
  grantedAt: string;
  expiresAt: string | null;
};
type ShareLink = {
  id: string;
  documentId: string;
  canDownload: boolean;
  hasPassword: boolean;
  expiresAt: string;
  singleUse: boolean;
  useCount: number;
  revokedAt: string | null;
  createdAt: string;
};
type Audit = {
  id: string;
  sequence: number;
  eventType: string;
  actorEmail: string | null;
  targetType: string | null;
  targetId: string | null;
  outcome: string;
  ipAddress: string | null;
  metadata: Record<string, unknown>;
  recordHash: string;
  prevHash: string | null;
  createdAt: string;
};
const roles: Role[] = [
  "STANDARD_USER",
  "DOCUMENT_OWNER",
  "AUDITOR",
  "ADMINISTRATOR",
];
function message(error: unknown): string {
  const body = (error as { response?: { data?: ErrorBody } })?.response?.data;
  return (
    body?.error?.message ??
    "The request could not be completed. Check the details and try again."
  );
}
function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1048576).toFixed(1)} MB`;
}
function date(value: string | null | undefined): string {
  return value
    ? new Intl.DateTimeFormat(undefined, {
        dateStyle: "medium",
        timeStyle: "short",
      }).format(new Date(value))
    : "Never";
}
function Shell({ children }: { children: React.ReactNode }) {
  const { user, logout } = useAuth();
  const location = useLocation();
  if (!user)
    return <Navigate to="/login" replace state={{ from: location.pathname }} />;
  const canAudit = user.role === "AUDITOR" || user.role === "ADMINISTRATOR";
  const canAdmin = user.role === "ADMINISTRATOR";
  return (
    <div className="shell">
      <aside className="sidebar">
        <Link
          className="brand"
          to="/documents"
          aria-label="SecureDocs documents"
        >
          <span className="brand-mark">SD</span>
          <span>SecureDocs</span>
        </Link>
        <p className="sidebar-note">Records custody</p>
        <nav aria-label="Primary navigation">
          <Link
            className={
              location.pathname.startsWith("/documents") ? "active" : ""
            }
            to="/documents"
          >
            Documents
          </Link>
          {canAudit && (
            <Link
              className={location.pathname.startsWith("/audit") ? "active" : ""}
              to="/audit"
            >
              Audit trail
            </Link>
          )}
          {canAdmin && (
            <Link
              className={location.pathname.startsWith("/admin") ? "active" : ""}
              to="/admin"
            >
              Administration
            </Link>
          )}
        </nav>
        <div className="account">
          <strong>{user.displayName}</strong>
          <span>{user.role.replaceAll("_", " ")}</span>
          <button className="link-button" onClick={() => void logout()}>
            Sign out
          </button>
        </div>
      </aside>
      <main className="main">{children}</main>
    </div>
  );
}
function Loading() {
  return (
    <div className="state">
      <span className="loader" aria-hidden="true" />
      Loading records...
    </div>
  );
}
function ErrorState({ text, retry }: { text: string; retry?: () => void }) {
  return (
    <div className="state error-state">
      <strong>{text}</strong>
      {retry && (
        <button className="button secondary" onClick={retry}>
          Try again
        </button>
      )}
    </div>
  );
}
function Button({
  children,
  ...props
}: {
  children: React.ReactNode;
  className?: string;
  type?: "button" | "submit";
  disabled?: boolean;
  onClick?: () => void;
}) {
  return (
    <button {...props} className={`button ${props.className ?? ""}`}>
      {children}
    </button>
  );
}
function PasswordField({
  label,
  value,
  onChange,
  autoComplete,
  required = false,
  minLength,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  autoComplete?: string;
  required?: boolean;
  minLength?: number;
}) {
  const [visible, setVisible] = useState(false);
  return (
    <label className="password-field">
      {label}
      <span className="password-control">
        <input
          required={required}
          minLength={minLength}
          type={visible ? "text" : "password"}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          autoComplete={autoComplete}
        />
        <button
          type="button"
          className="password-toggle"
          aria-label={visible ? "Hide password" : "Show password"}
          onClick={() => setVisible(!visible)}
        >
          {visible ? "Hide" : "Show"}
        </button>
      </span>
    </label>
  );
}
function AuthLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="auth-page">
      <div className="auth-aside">
        <span className="brand-mark">SD</span>
        <p>Keep a clear record of who can see what.</p>
      </div>
      <section className="auth-panel">{children}</section>
    </div>
  );
}
function Login() {
  const { login, user } = useAuth();
  const nav = useNavigate();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  if (user) return <Navigate to="/documents" replace />;
  async function submit(e: FormEvent) {
    e.preventDefault();
    setError("");
    try {
      await login(email, password);
      nav("/documents");
    } catch (err) {
      setError(message(err));
    }
  }
  return (
    <AuthLayout>
      <div className="auth-heading">
        <h1>Welcome back</h1>
        <p>Sign in to your document ledger.</p>
      </div>
      <form onSubmit={submit} className="form-stack">
        {error && (
          <div className="alert danger" role="alert">
            {error}
          </div>
        )}
        <label>
          Email
          <input
            required
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            autoComplete="email"
          />
        </label>
        <PasswordField
          label="Password"
          value={password}
          onChange={setPassword}
          autoComplete="current-password"
          required
        />
        <Button type="submit">Sign in</Button>
      </form>
      <p className="auth-foot">
        Need an account? <Link to="/register">Register</Link>
      </p>
    </AuthLayout>
  );
}
function Register() {
  const { register } = useAuth();
  const nav = useNavigate();
  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [error, setError] = useState("");
  const [registered, setRegistered] = useState(false);
  const valid = password.length >= 12;
  async function submit(e: FormEvent) {
    e.preventDefault();
    setError("");
    if (password !== confirmation) {
      setError("Passwords do not match.");
      return;
    }
    try {
      await register(email, name, password);
      setRegistered(true);
    } catch (err) {
      setError(message(err));
    }
  }
  return (
    <AuthLayout>
      {registered ? (
        <div className="registration-success" role="status">
          <h1>Account created</h1>
          <p>Your account was created successfully. Sign in to continue.</p>
          <Button onClick={() => nav("/login")}>Sign in</Button>
        </div>
      ) : (
        <>
          <div className="auth-heading">
            <h1>Create your account</h1>
            <p>Use your organisation email to get started.</p>
          </div>
          <form onSubmit={submit} className="form-stack">
            {error && (
              <div className="alert danger" role="alert">
                {error}
              </div>
            )}
            <label>
              Email
              <input
                required
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                autoComplete="email"
              />
            </label>
            <label>
              Display name
              <input
                required
                value={name}
                onChange={(e) => setName(e.target.value)}
                autoComplete="name"
              />
            </label>
            <PasswordField
              label="Password"
              value={password}
              onChange={setPassword}
              autoComplete="new-password"
              required
              minLength={12}
            />
            <PasswordField
              label="Confirm password"
              value={confirmation}
              onChange={setConfirmation}
              autoComplete="new-password"
              required
            />
            <label>
              <span className={valid ? "hint good" : "hint"}>
                {valid
                  ? "Password meets the 12-character minimum."
                  : `${password.length}/12 characters`}
              </span>
            </label>
            <Button type="submit">Create account</Button>
          </form>
          <p className="auth-foot">
            Already registered? <Link to="/login">Sign in</Link>
          </p>
        </>
      )}
    </AuthLayout>
  );
}
function PageHeader({
  title,
  children,
}: {
  title: string;
  children?: React.ReactNode;
}) {
  return (
    <header className="page-header">
      <div>
        <span className="eyebrow">SECUREDOCS</span>
        <h1>{title}</h1>
      </div>
      <div className="header-actions">{children}</div>
    </header>
  );
}
function Documents() {
  const nav = useNavigate();
  const [items, setItems] = useState<Document[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
  const [category, setCategory] = useState("");
  const [scope, setScope] = useState("all");
  const [sortBy, setSortBy] = useState("createdAt");
  const [sortDir, setSortDir] = useState("desc");
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const [pageSize] = useState(20);
  const { user } = useAuth();
  async function load() {
    setLoading(true);
    setError("");
    try {
      const r = await api.get<{ items: Document[]; total: number }>(
        "/documents",
        {
          params: { page, pageSize, search, category, scope, sortBy, sortDir },
        },
      );
      setItems(r.data.items);
      setTotal(r.data.total);
    } catch (err) {
      setError(message(err));
    } finally {
      setLoading(false);
    }
  }
  useEffect(() => {
    void load();
  }, [page, search, category, scope, sortBy, sortDir]);
  function sort(column: string) {
    setSortDir(sortBy === column && sortDir === "asc" ? "desc" : "asc");
    setSortBy(column);
  }
  return (
    <Shell>
      <PageHeader title="Documents">
        <Button onClick={() => nav("/upload")}>Upload document</Button>
      </PageHeader>
      <section className="toolbar" aria-label="Document filters">
        <label className="search-label">
          Search
          <input
            placeholder="Search titles or names"
            value={search}
            onChange={(e) => {
              setPage(1);
              setSearch(e.target.value);
            }}
          />
        </label>
        <label>
          Category
          <select
            value={category}
            onChange={(e) => {
              setPage(1);
              setCategory(e.target.value);
            }}
          >
            <option value="">All categories</option>
            <option value="LEGAL">Legal</option>
            <option value="FINANCE">Finance</option>
            <option value="HR">HR</option>
            <option value="GENERAL">General</option>
          </select>
        </label>
        <div className="tabs" role="tablist">
          <button
            className={scope === "all" ? "selected" : ""}
            onClick={() => {
              setPage(1);
              setScope("all");
            }}
          >
            All
          </button>
          <button
            className={scope === "owned" ? "selected" : ""}
            onClick={() => {
              setPage(1);
              setScope("owned");
            }}
          >
            Owned
          </button>
          <button
            className={scope === "shared" ? "selected" : ""}
            onClick={() => {
              setPage(1);
              setScope("shared");
            }}
          >
            Shared with me
          </button>
        </div>
      </section>
      {loading ? (
        <Loading />
      ) : error ? (
        <ErrorState text={error} retry={() => void load()} />
      ) : items.length === 0 ? (
        <div className="empty">
          <h2>Upload your first document</h2>
          <p>Your secure ledger will appear here when you add a record.</p>
          <Button onClick={() => nav("/upload")}>Upload document</Button>
        </div>
      ) : (
        <>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  {[
                    ["Title", "title"],
                    ["Category", "category"],
                    ["Owner", "ownerEmail"],
                    ["Size", "sizeBytes"],
                    ["Access", "accessLevel"],
                    ["Uploaded", "createdAt"],
                  ].map(([label, key]) => (
                    <th key={key}>
                      <button className="sort-button" onClick={() => sort(key)}>
                        {label}
                        {sortBy === key && (
                          <span aria-label={sortDir}>
                            {sortDir === "asc" ? " ↑" : " ↓"}
                          </span>
                        )}
                      </button>
                    </th>
                  ))}
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {items.map((item) => (
                  <tr key={item.id}>
                    <td>
                      <Link
                        className="document-title"
                        to={`/documents/${item.id}`}
                      >
                        {item.title}
                      </Link>
                      <span className="subtext">{item.originalName}</span>
                    </td>
                    <td>{item.category}</td>
                    <td>{item.ownerEmail}</td>
                    <td>{formatBytes(item.sizeBytes)}</td>
                    <td>
                      <span
                        className={`badge ${item.accessLevel.toLowerCase()}`}
                      >
                        {item.accessLevel}
                      </span>
                    </td>
                    <td>{date(item.createdAt)}</td>
                    <td>
                      <button
                        className="table-action"
                        onClick={() => nav(`/documents/${item.id}`)}
                      >
                        Open
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="pagination">
            <span>{total} records</span>
            <button disabled={page === 1} onClick={() => setPage(page - 1)}>
              Previous
            </button>
            <span>
              Page {page} of {Math.max(1, Math.ceil(total / pageSize))}
            </span>
            <button
              disabled={page * pageSize >= total}
              onClick={() => setPage(page + 1)}
            >
              Next
            </button>
          </div>
        </>
      )}
    </Shell>
  );
}
function Upload() {
  const nav = useNavigate();
  const [file, setFile] = useState<File | null>(null);
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [category, setCategory] = useState("GENERAL");
  const [progress, setProgress] = useState(0);
  const [error, setError] = useState("");
  const input = useRef<HTMLInputElement>(null);
  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!file) {
      setError("Choose a file before uploading.");
      return;
    }
    setError("");
    const form = new FormData();
    form.append("file", file);
    form.append("title", title);
    if (description) form.append("description", description);
    form.append("category", category);
    try {
      const r = await api.post<{ document: Document }>("/documents", form, {
        onUploadProgress: (e) =>
          setProgress(e.total ? Math.round((e.loaded / e.total) * 100) : 50),
      });
      nav(`/documents/${r.data.document.id}`);
    } catch (err) {
      setError(message(err));
      setProgress(0);
    }
  }
  return (
    <Shell>
      <PageHeader title="Upload document" />
      <form className="upload-layout" onSubmit={submit}>
        <section className="panel">
          <div
            className={`dropzone ${file ? "has-file" : ""}`}
            onClick={() => input.current?.click()}
            onDragOver={(e) => e.preventDefault()}
            onDrop={(e) => {
              e.preventDefault();
              const dropped = e.dataTransfer.files[0];
              if (dropped) setFile(dropped);
            }}
          >
            <input
              ref={input}
              type="file"
              hidden
              onChange={(e) => setFile(e.target.files?.[0] ?? null)}
            />
            <strong>
              {file ? file.name : "Choose a file or drag it here"}
            </strong>
            <span>
              {file
                ? formatBytes(file.size)
                : "The server validates type, content and malware signatures."}
            </span>
          </div>
          {error && (
            <div className="alert danger upload-error" role="alert">
              <strong>Upload rejected</strong>
              <span>{error}</span>
            </div>
          )}
          {progress > 0 && (
            <div className="progress">
              <span style={{ width: `${progress}%` }} />
              <span className="sr-only">Upload progress {progress}%</span>
            </div>
          )}
        </section>
        <section className="panel form-stack">
          <label>
            Title
            <input
              required
              value={title}
              onChange={(e) => setTitle(e.target.value)}
            />
          </label>
          <label>
            Description
            <textarea
              rows={4}
              value={description}
              onChange={(e) => setDescription(e.target.value)}
            />
          </label>
          <label>
            Category
            <select
              value={category}
              onChange={(e) => setCategory(e.target.value)}
            >
              <option>GENERAL</option>
              <option>LEGAL</option>
              <option>FINANCE</option>
              <option>HR</option>
            </select>
          </label>
          <Button type="submit" disabled={progress > 0}>
            Upload document
          </Button>
        </section>
      </form>
    </Shell>
  );
}
function DocumentDetail() {
  const { id } = useParams();
  const nav = useNavigate();
  const { user } = useAuth();
  const [doc, setDoc] = useState<Document | null>(null);
  const [permissions, setPermissions] = useState<Permission[]>([]);
  const [links, setLinks] = useState<ShareLink[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [grantError, setGrantError] = useState("");
  const [shareError, setShareError] = useState("");
  const [granteeEmail, setGranteeEmail] = useState("");
  const [grant, setGrant] = useState({
    canView: true,
    canDownload: false,
    canReshare: false,
  });
  const [share, setShare] = useState({
    expiresInHours: 24,
    canDownload: true,
    singleUse: false,
    password: "",
  });
  const [createdToken, setCreatedToken] = useState("");
  async function load() {
    if (!id) return;
    setLoading(true);
    try {
      const r = await api.get<{
        document: Document;
        permissions: Permission[];
        shareLinks: ShareLink[];
      }>(`/documents/${id}`);
      setDoc(r.data.document);
      setPermissions(r.data.permissions);
      setLinks(r.data.shareLinks);
    } catch (err) {
      setError(message(err));
    } finally {
      setLoading(false);
    }
  }
  useEffect(() => {
    void load();
  }, [id]);
  async function download() {
    try {
      const r = await api.get(`/documents/${id}/download`, {
        responseType: "blob",
      });
      const url = URL.createObjectURL(r.data);
      const a = document.createElement("a");
      a.href = url;
      a.download = doc?.originalName ?? "document";
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      setError(message(err));
    }
  }
  async function grantAccess(e: FormEvent) {
    e.preventDefault();
    setGrantError("");
    try {
      const r = await api.post<{ permission: Permission }>(
        `/documents/${id}/permissions`,
        { granteeEmail, ...grant },
      );
      setPermissions([...permissions, r.data.permission]);
      setGranteeEmail("");
      setNotice("Access granted");
    } catch (err) {
      setGrantError(message(err));
    }
  }
  async function revoke(permissionId: string) {
    try {
      await api.delete(`/documents/${id}/permissions/${permissionId}`);
      setPermissions(permissions.filter((p) => p.id !== permissionId));
      setNotice("Access revoked");
    } catch (err) {
      setError(message(err));
    }
  }
  async function createShare(e: FormEvent) {
    e.preventDefault();
    setShareError("");
    try {
      const r = await api.post<{
        shareLink: ShareLink;
        url: string;
        token: string;
      }>(`/documents/${id}/share`, {
        expiresInHours: share.expiresInHours,
        canDownload: share.canDownload,
        singleUse: share.singleUse,
        ...(share.password ? { password: share.password } : {}),
      });
      setLinks([...links, r.data.shareLink]);
      setCreatedToken(`${r.data.url}`);
      setNotice("Share link created");
    } catch (err) {
      setShareError(message(err));
    }
  }
  async function revokeShare(linkId: string) {
    try {
      await api.delete(`/share/${linkId}`);
      setLinks(
        links.map((link) =>
          link.id === linkId
            ? { ...link, revokedAt: new Date().toISOString() }
            : link,
        ),
      );
      setNotice("Share link revoked");
    } catch (err) {
      setError(message(err));
    }
  }
  if (loading)
    return (
      <Shell>
        <Loading />
      </Shell>
    );
  if (error && !doc)
    return (
      <Shell>
        <ErrorState text={error} />
      </Shell>
    );
  if (!doc) return null;
  const owner = doc.ownerId === user?.id;
  return (
    <Shell>
      <PageHeader title={doc.title}>
        <Button className="secondary" onClick={() => nav("/documents")}>
          Back to documents
        </Button>
        <Button onClick={() => void download()}>Download</Button>
      </PageHeader>
      {error && (
        <div className="alert danger" role="alert">
          {error}
        </div>
      )}
      {notice && (
        <div className="alert success" role="status">
          {notice}
        </div>
      )}
      <div className="detail-grid">
        <section className="panel metadata">
          <h2>Document record</h2>
          <dl>
            <dt>Original file</dt>
            <dd>{doc.originalName}</dd>
            <dt>Category</dt>
            <dd>{doc.category}</dd>
            <dt>Size</dt>
            <dd>{formatBytes(doc.sizeBytes)}</dd>
            <dt>Owner</dt>
            <dd>{doc.ownerEmail}</dd>
            <dt>Scan verdict</dt>
            <dd>{doc.scanVerdict}</dd>
            <dt>Updated</dt>
            <dd>{date(doc.updatedAt)}</dd>
          </dl>
          <div className="digest">
            <span>SHA-256</span>
            <div>
              <code className="mono">{doc.sha256}</code>
              <button
                className="copy-button"
                onClick={() => {
                  void navigator.clipboard.writeText(doc.sha256);
                  setNotice("Digest copied");
                }}
              >
                Copy
              </button>
            </div>
          </div>
        </section>
        {permissions.length > 0 || owner ? (
          <section className="panel">
            <h2>Who can see this</h2>
            {owner && (
              <form onSubmit={grantAccess} className="grant-form">
                <label>
                  Grant access by email
                  <input
                    required
                    type="email"
                    value={granteeEmail}
                    onChange={(e) => setGranteeEmail(e.target.value)}
                  />
                </label>
                {grantError && (
                  <div className="field-error" role="alert">
                    {grantError}
                  </div>
                )}
                <div className="check-row">
                  <label>
                    <input
                      type="checkbox"
                      checked={grant.canView}
                      onChange={(e) =>
                        setGrant({ ...grant, canView: e.target.checked })
                      }
                    />{" "}
                    View
                  </label>
                  <label>
                    <input
                      type="checkbox"
                      checked={grant.canDownload}
                      onChange={(e) =>
                        setGrant({ ...grant, canDownload: e.target.checked })
                      }
                    />{" "}
                    Download
                  </label>
                  <label>
                    <input
                      type="checkbox"
                      checked={grant.canReshare}
                      onChange={(e) =>
                        setGrant({ ...grant, canReshare: e.target.checked })
                      }
                    />{" "}
                    Reshare
                  </label>
                </div>
                <Button type="submit">Grant access</Button>
              </form>
            )}
            <div className="permission-list">
              {permissions.length === 0 ? (
                <p className="subtext">No one else currently has access.</p>
              ) : (
                permissions.map((p) => (
                  <div className="permission" key={p.id}>
                    <div>
                      <strong>{p.granteeName}</strong>
                      <span>{p.granteeEmail}</span>
                      <small>
                        {[
                          p.canView && "View",
                          p.canDownload && "Download",
                          p.canReshare && "Reshare",
                        ]
                          .filter(Boolean)
                          .join(" · ")}
                      </small>
                    </div>
                    {owner && (
                      <button
                        className="danger-link"
                        onClick={() => void revoke(p.id)}
                      >
                        Revoke access
                      </button>
                    )}
                  </div>
                ))
              )}
            </div>
          </section>
        ) : null}
        {permissions.length > 0 || owner ? (
          <section className="panel share-panel">
            <h2>Share links</h2>
            {owner && (
              <form onSubmit={createShare} className="share-form">
                <label>
                  Expires in hours
                  <input
                    required
                    min={1}
                    max={720}
                    type="number"
                    value={share.expiresInHours}
                    onChange={(e) =>
                      setShare({
                        ...share,
                        expiresInHours: Number(e.target.value),
                      })
                    }
                  />
                </label>
                <label className="check-label">
                  <input
                    type="checkbox"
                    checked={share.singleUse}
                    onChange={(e) =>
                      setShare({ ...share, singleUse: e.target.checked })
                    }
                  />{" "}
                  Single use
                </label>
                <label className="check-label">
                  <input
                    type="checkbox"
                    checked={share.canDownload}
                    onChange={(e) =>
                      setShare({ ...share, canDownload: e.target.checked })
                    }
                  />{" "}
                  Allow download
                </label>
                <label>
                  Password (optional)
                  <input
                    type="password"
                    value={share.password}
                    onChange={(e) =>
                      setShare({ ...share, password: e.target.value })
                    }
                  />
                </label>
                <Button type="submit">Create share link</Button>
                {shareError && (
                  <div className="field-error" role="alert">
                    {shareError}
                  </div>
                )}
              </form>
            )}
            {createdToken && (
              <div className="token-block">
                <strong>Save this link now</strong>
                <p>
                  This link will not be shown again after you dismiss this
                  message.
                </p>
                <code className="mono">{createdToken}</code>
                <div>
                  <button
                    className="copy-button"
                    onClick={() => {
                      void navigator.clipboard.writeText(createdToken);
                      setNotice("Share link copied");
                    }}
                  >
                    Copy link
                  </button>
                  <button
                    className="copy-button"
                    onClick={() => setCreatedToken("")}
                  >
                    Dismiss
                  </button>
                </div>
              </div>
            )}
            <div className="link-list">
              {links
                .filter((l) => !l.revokedAt)
                .map((l) => (
                  <div className="share-link" key={l.id}>
                    <div>
                      <code className="mono">{l.id}</code>
                      <span>
                        Expires {date(l.expiresAt)} ·{" "}
                        {l.singleUse ? "Single use" : "Reusable"}
                        {l.hasPassword ? " · Password protected" : ""}
                      </span>
                    </div>
                    {owner && (
                      <button
                        className="danger-link"
                        onClick={() => void revokeShare(l.id)}
                      >
                        Revoke link
                      </button>
                    )}
                  </div>
                ))}
              {links.filter((l) => !l.revokedAt).length === 0 && (
                <p className="subtext">
                  Create a link when someone outside SecureDocs needs access.
                </p>
              )}
            </div>
          </section>
        ) : null}
      </div>
    </Shell>
  );
}
function PublicShare() {
  const { token } = useParams();
  const [doc, setDoc] = useState<{
    title: string;
    originalName: string;
    mimeType: string;
    sizeBytes: number;
  } | null>(null);
  const [requiresPassword, setRequiresPassword] = useState(false);
  const [password, setPassword] = useState("");
  const [passwordVisible, setPasswordVisible] = useState(false);
  const [error, setError] = useState(false);
  useEffect(() => {
    api
      .get<{ document: typeof doc; requiresPassword: boolean }>(
        `/share/${token}`,
      )
      .then((r) => {
        setDoc(r.data.document);
        setRequiresPassword(r.data.requiresPassword);
      })
      .catch(() => setError(true));
  }, [token]);
  async function download(e: FormEvent) {
    e.preventDefault();
    try {
      const r = await api.post(
        `/share/${token}/download`,
        requiresPassword ? { password } : {},
        { responseType: "blob" },
      );
      const url = URL.createObjectURL(r.data);
      const a = document.createElement("a");
      a.href = url;
      a.download = doc?.originalName ?? "document";
      a.click();
      URL.revokeObjectURL(url);
    } catch {
      setError(true);
    }
  }
  return (
    <div className="public-page">
      <div className="public-box">
        <div className="brand">
          <span className="brand-mark">SD</span>
          <span>SecureDocs</span>
        </div>
        {error ? (
          <>
            <h1>This link is not available</h1>
            <p>The link may have expired, been revoked, or already used.</p>
          </>
        ) : !doc ? (
          <Loading />
        ) : (
          <>
            <span className="eyebrow">SECURE SHARE</span>
            <h1>{doc.title}</h1>
            <p>
              {doc.originalName} · {formatBytes(doc.sizeBytes)}
            </p>
            <form className="form-stack" onSubmit={download}>
              {requiresPassword && (
                <label className="password-field">
                  Password
                  <span className="password-control">
                    <input
                      required
                      type={passwordVisible ? "text" : "password"}
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                    />
                    <button
                      type="button"
                      className="password-toggle"
                      aria-label={
                        passwordVisible ? "Hide password" : "Show password"
                      }
                      onClick={() => setPasswordVisible(!passwordVisible)}
                    >
                      {passwordVisible ? "Hide" : "Show"}
                    </button>
                  </span>
                </label>
              )}
              <Button type="submit">Download document</Button>
            </form>
          </>
        )}
      </div>
    </div>
  );
}
function Audit() {
  const [items, setItems] = useState<Audit[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [valid, setValid] = useState<boolean | null>(null);
  const [broken, setBroken] = useState<number | null>(null);
  const [eventType, setEventType] = useState("");
  const [actorEmail, setActorEmail] = useState("");
  const [outcome, setOutcome] = useState("");
  async function load() {
    setLoading(true);
    try {
      const r = await api.get<{ items: Audit[] }>("/audit", {
        params: { page: 1, pageSize: 100, eventType, actorEmail, outcome },
      });
      setItems(r.data.items);
    } catch (err) {
      setError(message(err));
    } finally {
      setLoading(false);
    }
  }
  useEffect(() => {
    void load();
  }, [eventType, actorEmail, outcome]);
  async function verify() {
    try {
      const r = await api.get<{
        valid: boolean;
        brokenAtSequence: number | null;
      }>("/audit/verify");
      setValid(r.data.valid);
      setBroken(r.data.brokenAtSequence);
    } catch (err) {
      setError(message(err));
    }
  }
  async function exportCsv() {
    const r = await api.get("/audit/export", { responseType: "blob" });
    const url = URL.createObjectURL(r.data);
    const a = document.createElement("a");
    a.href = url;
    a.download = "audit-export.csv";
    a.click();
    URL.revokeObjectURL(url);
  }
  return (
    <Shell>
      <PageHeader title="Audit trail">
        <Button className="secondary" onClick={() => void exportCsv()}>
          Export CSV
        </Button>
        <Button onClick={() => void verify()}>Verify chain integrity</Button>
      </PageHeader>
      <section className="toolbar audit-filters">
        <label>
          Event type
          <input
            placeholder="e.g. DOC_VIEW"
            value={eventType}
            onChange={(e) => setEventType(e.target.value)}
          />
        </label>
        <label>
          Actor email
          <input
            type="email"
            value={actorEmail}
            onChange={(e) => setActorEmail(e.target.value)}
          />
        </label>
        <label>
          Outcome
          <select value={outcome} onChange={(e) => setOutcome(e.target.value)}>
            <option value="">All outcomes</option>
            <option>SUCCESS</option>
            <option>FAILURE</option>
            <option>DENIED</option>
          </select>
        </label>
      </section>
      {valid !== null && (
        <div
          className={`verify-result ${valid ? "valid" : "broken"}`}
          role="status"
        >
          <strong>
            {valid ? "Chain integrity verified" : "Chain integrity broken"}
          </strong>
          <span>
            {valid
              ? "Every record hash links correctly."
              : `Broken at sequence ${broken ?? "unknown"}.`}
          </span>
        </div>
      )}
      {loading ? (
        <Loading />
      ) : error ? (
        <ErrorState text={error} retry={() => void load()} />
      ) : (
        <div className="audit-chain">
          {items.map((entry, index) => {
            const severed = broken !== null && entry.sequence === broken;
            return (
              <article
                className={`audit-entry ${severed ? "severed" : ""}`}
                key={entry.id}
              >
                <div className="chain-node" aria-hidden="true" />
                <div className="audit-content">
                  <div className="audit-top">
                    <span className="sequence">#{entry.sequence}</span>
                    <strong>{entry.eventType}</strong>
                    <span className={`outcome ${entry.outcome.toLowerCase()}`}>
                      {entry.outcome}
                    </span>
                  </div>
                  <p>
                    {entry.actorEmail ?? "System"}{" "}
                    <span className="muted">
                      · {entry.targetType ?? "Event"}
                      {entry.targetId ? ` ${entry.targetId}` : ""}
                    </span>
                  </p>
                  <div className="audit-meta">
                    <code className="mono">
                      {entry.recordHash.slice(0, 12)}
                    </code>
                    <span>{date(entry.createdAt)}</span>
                    <span>{entry.ipAddress ?? "No IP"}</span>
                  </div>
                </div>
              </article>
            );
          })}
        </div>
      )}
    </Shell>
  );
}
function Admin() {
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  async function load() {
    try {
      const r = await api.get<{ users: User[] }>("/admin/users");
      setUsers(r.data.users);
    } catch (err) {
      setError(message(err));
    } finally {
      setLoading(false);
    }
  }
  useEffect(() => {
    void load();
  }, []);
  async function update(id: string, body: { role?: Role; status?: string }) {
    try {
      const r = await api.patch<{ user: User }>(`/admin/users/${id}`, body);
      setUsers(users.map((user) => (user.id === id ? r.data.user : user)));
    } catch (err) {
      setError(message(err));
    }
  }
  return (
    <Shell>
      <PageHeader title="Administration" />
      <p className="intro">
        Manage roles and account access for SecureDocs users.
      </p>
      {loading ? (
        <Loading />
      ) : error ? (
        <ErrorState text={error} retry={() => void load()} />
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Email</th>
                <th>Role</th>
                <th>Status</th>
                <th>Last login</th>
              </tr>
            </thead>
            <tbody>
              {users.map((user) => (
                <tr key={user.id}>
                  <td>{user.displayName}</td>
                  <td>{user.email}</td>
                  <td>
                    <label className="sr-only" htmlFor={`role-${user.id}`}>
                      Role for {user.email}
                    </label>
                    <select
                      id={`role-${user.id}`}
                      value={user.role}
                      onChange={(e) =>
                        void update(user.id, { role: e.target.value as Role })
                      }
                    >
                      {roles.map((role) => (
                        <option key={role}>{role}</option>
                      ))}
                    </select>
                  </td>
                  <td>
                    <label className="toggle">
                      <input
                        type="checkbox"
                        checked={user.status === "ACTIVE"}
                        onChange={(e) =>
                          void update(user.id, {
                            status: e.target.checked ? "ACTIVE" : "SUSPENDED",
                          })
                        }
                      />
                      <span>{user.status}</span>
                    </label>
                  </td>
                  <td>{date(user.lastLoginAt)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Shell>
  );
}
function Guard({
  children,
  allowed,
}: {
  children: React.ReactNode;
  allowed: Role[];
}) {
  const { user } = useAuth();
  return user && allowed.includes(user.role) ? (
    <>{children}</>
  ) : (
    <Navigate to="/documents" replace />
  );
}
export function App() {
  const { loading } = useAuth();
  if (loading) return <Loading />;
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route path="/register" element={<Register />} />
      <Route path="/share/:token" element={<PublicShare />} />
      <Route path="/documents" element={<Documents />} />
      <Route path="/documents/:id" element={<DocumentDetail />} />
      <Route path="/upload" element={<Upload />} />
      <Route
        path="/audit"
        element={
          <Guard allowed={["AUDITOR", "ADMINISTRATOR"]}>
            <Audit />
          </Guard>
        }
      />
      <Route
        path="/admin"
        element={
          <Guard allowed={["ADMINISTRATOR"]}>
            <Admin />
          </Guard>
        }
      />
      <Route path="*" element={<Navigate to="/documents" replace />} />
    </Routes>
  );
}
