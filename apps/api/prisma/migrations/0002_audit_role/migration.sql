-- Demonstration of the restricted audit role. In production the application would connect
-- as this role; Prisma migrations require broader rights, so this is not fully enforced here.
DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'securedocs_audit_writer') THEN
    CREATE ROLE securedocs_audit_writer;
  END IF;
END $$;
REVOKE UPDATE, DELETE ON TABLE "AuditLog" FROM securedocs_audit_writer;
