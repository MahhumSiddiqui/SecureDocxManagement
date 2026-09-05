# 06 — Frontend

Build in `apps/web` against the contract in `03-API-CONTRACT.md`. Every screen reads
real API responses. No mock data, no placeholder arrays, anywhere.

## Design direction

This is a records-custody system used by office administrators, compliance staff and
department managers. The question they need answered fastest is *who can currently
see this document*. Design for that, not for a generic SaaS dashboard.

**Colour tokens** — define in `styles/tokens.css` and extend Tailwind's theme:

```css
--ink:    #14202E;  /* primary text, sidebar */
--paper:  #F7F5F1;  /* page background */
--slate:  #4A6E8C;  /* interactive, links, primary buttons */
--sand:   #E8E2D8;  /* surfaces, dividers, table rules */
--amber:  #B87333;  /* warnings, expiring access */
--rust:   #9B3B2F;  /* denials, revocation, destructive */
--white:  #FFFFFF;
```

No gradients. No coloured drop shadows.

**Type.** Source Sans 3 for the whole interface (Google Fonts). JetBrains Mono
*only* for SHA-256 digests, UUIDs and share tokens — there the fixed width is
functional, because users compare those character by character. Do not use mono for
ordinary labels or metadata. Scale: 12 / 14 / 16 / 20 / 28 px, weights 400 / 600 only.

**Layout.** Fixed 220px left sidebar in `--ink` with the nav; content area on
`--paper`, max width 1200px, left-aligned. No top navigation duplicating the sidebar.

**The document list is a dense table, not a grid of cards.** This is a records system —
rows let people scan ownership and access state down a column. Columns: Title,
Category, Owner, Size, Access (OWNER or SHARED badge), Uploaded, Actions.

**Spend the visual interest in one place: the audit trail.** Render it as a
continuous vertical chain — each entry connected to the one above by a visible
2px line in `--sand`, with the first 12 characters of `recordHash` shown in mono
beside each node. When `GET /audit/verify` reports a break, the connector below the
broken record turns `--rust` and the chain visibly severs. This makes the
tamper-evident structure legible in the interface instead of hidden in the database.
Keep everything else quiet.

**Avoid:** all-caps eyebrow labels above headings · identical rounded cards for
dissimilar content · a soft grey shadow under every element · fade-and-slide
entrance animations on sections · `→` appended to button text · one accent-coloured
word inside a headline.

## Copy rules

Active voice, sentence case. Buttons name what happens: "Revoke access", not "Submit".
The action keeps its name through the flow — a "Revoke access" button produces an
"Access revoked" toast. Errors say what went wrong and what to do next; they don't
apologise and they're never vague. Empty states invite an action rather than stating
emptiness ("Upload your first document" beats "No documents found").

## Quality floor

Responsive down to 375px · visible keyboard focus rings on every interactive element ·
`prefers-reduced-motion` respected · WCAG AA contrast · every form input has an
associated `<label>` · all user text rendered through React's default escaping —
**never `dangerouslySetInnerHTML` in secure mode**.

## Screens

| Route | Contents |
|---|---|
| `/login` | Email, password. Inline error. Link to register. |
| `/register` | Email, name, password with a live 12-character check. |
| `/documents` | The ledger table. Search box, category filter, scope tabs (All / Owned / Shared with me), sortable columns, pagination. Upload button. |
| `/documents/:id` | Metadata panel; SHA-256 in mono with a copy button; Download; permissions panel (grant by email with view/download/reshare checkboxes, revoke); share links panel (create with expiry hours, single-use, optional password; the token is shown **once** in a dismissable block with a copy button and a warning that it will not be shown again; list of active links with revoke). Permissions and share panels appear only when the API returns them. |
| `/upload` | Drag-or-select, title, description, category. Progress bar. On rejection, show the API's specific reason prominently — a rejected upload is a security control working, so make it legible rather than a generic failure. |
| `/share/:token` | Public, unauthenticated. Document name and size, password field if required, Download button. On any failure show one generic "This link is not available" message. |
| `/audit` | AUDITOR and ADMINISTRATOR only. Filters (event type, actor email, outcome, date range). The chain visualisation. "Verify chain integrity" button showing valid / broken-at-sequence. Export CSV. |
| `/admin` | ADMINISTRATOR only. User table with role dropdown and suspend toggle. |

Sidebar shows only the routes the current role can reach — but the backend enforces
access regardless, and hiding a link is never the control.

## API client

`api/client.ts`: axios instance, `baseURL: http://127.0.0.1:3000/api`,
`withCredentials: true`. Request interceptor attaches the bearer token and the
`X-CSRF-Token` header from the `sd_csrf` cookie. Response interceptor: on 401, try
`POST /auth/refresh` **once**, replay the original request, and redirect to `/login`
if refresh fails. Guard against infinite refresh loops with a flag.

`context/AuthContext.tsx` holds the access token in memory only — never
`localStorage`, because a token in `localStorage` is readable by any injected script.
Comment on this. On mount, attempt a refresh to restore the session.

Every page has real loading and error states. Never render a blank screen while
fetching.