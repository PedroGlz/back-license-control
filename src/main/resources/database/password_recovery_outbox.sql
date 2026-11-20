-- Migración idempotente. Aplicar manualmente antes de desplegar el backend que usa el outbox.
CREATE TABLE IF NOT EXISTS password_recovery_rate_limits (
  Rate_Key CHAR(64) NOT NULL,
  Next_Allowed_At DATETIME(6) NOT NULL,
  Updated_At DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  PRIMARY KEY (Rate_Key),
  KEY idx_password_recovery_rate_limits_expiry (Next_Allowed_At)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS password_recovery_outbox (
  Id_Outbox CHAR(36) NOT NULL,
  Id_Request CHAR(36) NOT NULL,
  Id_User CHAR(38) NOT NULL,
  Requested_System VARCHAR(80) NOT NULL,
  Recipient_Email VARCHAR(254) NOT NULL,
  Recipient_Name VARCHAR(255) NULL,
  Encrypted_Secret LONGTEXT NULL,
  Expires_At DATETIME(6) NOT NULL,
  Credential_Expires_At DATETIME(6) NOT NULL,
  Previous_Password_Hash VARCHAR(255) NULL,
  Previous_Must_Change_Password BOOLEAN NOT NULL DEFAULT FALSE,
  Previous_Temporary_Password_Expires_At DATETIME(6) NULL,
  Issued_Auth_Version INT NOT NULL,
  Issued_Password_Hash VARCHAR(255) NULL,
  Status VARCHAR(20) NOT NULL DEFAULT 'PENDING',
  Attempt_Count INT NOT NULL DEFAULT 0,
  Next_Attempt_At DATETIME(6) NOT NULL,
  Locked_At DATETIME(6) NULL,
  Sent_At DATETIME(6) NULL,
  Last_Error_Code VARCHAR(80) NULL,
  Created_At DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (Id_Outbox),
  UNIQUE KEY uq_password_recovery_outbox_request (Id_Request),
  KEY idx_password_recovery_outbox_dispatch (Status, Next_Attempt_At),
  KEY idx_password_recovery_outbox_expiry (Status, Expires_At),
  KEY idx_password_recovery_outbox_user (Id_User, Created_At)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

SET @password_recovery_add_credential_expiry = IF(
  EXISTS(
    SELECT 1 FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'password_recovery_outbox'
      AND COLUMN_NAME = 'Credential_Expires_At'
  ),
  'SELECT 1',
  'ALTER TABLE password_recovery_outbox ADD COLUMN Credential_Expires_At DATETIME(6) NULL AFTER Expires_At'
);
PREPARE password_recovery_ddl FROM @password_recovery_add_credential_expiry;
EXECUTE password_recovery_ddl;
DEALLOCATE PREPARE password_recovery_ddl;

UPDATE password_recovery_outbox
SET Credential_Expires_At = Expires_At
WHERE Credential_Expires_At IS NULL;

ALTER TABLE password_recovery_outbox
  MODIFY COLUMN Credential_Expires_At DATETIME(6) NOT NULL;
