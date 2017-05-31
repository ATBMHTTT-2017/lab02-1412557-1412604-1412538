-- this is sample security requirement.
CREATE OR REPLACE FUNCTION VIEW_NHANVIEN(P_SCHEMA VARCHAR2, P_OBJECT VARCHAR2)
RETURN VARCHAR2
AS
BEGIN
  IF (SYS_CONTEXT('userenv', 'SESSION_USER') = 'QLDUAN') THEN
    RETURN '';
  END IF;
  RETURN 'MANV = ' || 'SYS_CONTEXT(''userenv'', ''SESSION_USER'')';
END;


BEGIN
  DBMS_RLS.ADD_POLICY(
    OBJECT_SCHEMA => 'QLDUAN',
    OBJECT_NAME => 'NHANVIEN',
    POLICY_NAME => 'VIEW_NHANVIEN',
    POLICY_FUNCTION => 'VIEW_NHANVIEN',
    SEC_RELEVANT_COLS => 'LUONG',
    SEC_RELEVANT_COLS_OPT => DBMS_RLS.ALL_ROWS);
END;

--EXEC DBMS_RLS.DROP_POLICY('QLDUAN', 'NHANVIEN', 'VIEW_NHANVIEN');
--DROP FUNCTION VIEW_NHANVIEN;


CREATE OR REPLACE FUNCTION enc_symmetric (plainText VARCHAR2) RETURN VARCHAR2 DETERMINISTIC
AS
    encrypted_raw      RAW (2000);
    encryption_type    PLS_INTEGER := DBMS_CRYPTO.ENCRYPT_AES256
                                 + DBMS_CRYPTO.CHAIN_CBC
                                 + DBMS_CRYPTO.PAD_PKCS5;
                                 
    encryption_key     RAW (32) := UTL_RAW.cast_to_raw('14125381412538141253814125381412');
BEGIN
    encrypted_raw := DBMS_CRYPTO.ENCRYPT
    (
       src => UTL_RAW.CAST_TO_RAW(plainText),
       typ => encryption_type,
       key => encryption_key
    );
   RETURN UTL_RAW.CAST_TO_VARCHAR2(encrypted_raw);
END;


 CREATE OR REPLACE FUNCTION dec_symmetric (cipherText VARCHAR2) RETURN VARCHAR2 DETERMINISTIC
 AS
    encryption_type    PLS_INTEGER := DBMS_CRYPTO.ENCRYPT_AES256
                                 + DBMS_CRYPTO.CHAIN_CBC
                                 + DBMS_CRYPTO.PAD_PKCS5;
                                 
    encryption_key     RAW (32) := UTL_RAW.cast_to_raw('14125381412538141253814125381412');
    decrypted_raw      RAW (2000);
BEGIN
    decrypted_raw := DBMS_CRYPTO.DECRYPT
    (
        src => UTL_RAW.CAST_TO_RAW(cipherText),
        typ => encryption_type,
        key => encryption_key
    );
    RETURN (UTL_RAW.CAST_TO_VARCHAR2(decrypted_raw));
END;
 
CREATE OR REPLACE TRIGGER INS_NHANVIEN
BEFORE INSERT
ON NHANVIEN
REFERENCING NEW AS NEW
FOR EACH ROW
BEGIN
  :NEW.luong := enc_symmetric(:NEW.luong);
END;

