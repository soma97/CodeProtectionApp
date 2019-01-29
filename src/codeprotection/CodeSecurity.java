package codeprotection;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.nio.file.Files;
import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Random;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.Alert;
import javafx.scene.control.ButtonType;
import javafx.scene.control.Label;
import javafx.scene.layout.BorderPane;
import javafx.stage.Stage;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class CodeSecurity {

    public static byte[] HashAlgorithm(String message, String algorithm) {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance(algorithm);
            byte[] hashedString = messageDigest.digest(message.getBytes("UTF8"));
            return hashedString;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String EncryptionAlgorithm(String message, String algorithm, SecretKey secretKey) {

        try {
            Cipher cipher = Cipher.getInstance(algorithm + "/ECB/PKCS5Padding", CertificationAuthority.bcProvider);
            byte[] text = message.getBytes("UTF8");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] cipherText = cipher.doFinal(text);
            return Base64.getEncoder().encodeToString(cipherText);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String DecryptionAlgorithm(String message, String algorithm, SecretKey secretKey) {
        byte[] cipherText = Base64.getDecoder().decode(message);
        try {
            Cipher cipher = Cipher.getInstance(algorithm + "/ECB/PKCS5Padding", CertificationAuthority.bcProvider);
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] plain = cipher.doFinal(cipherText);
            return new String(plain, "UTF8");
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static void EncryptFile(File file, String receiverUsername, String algorithm, String hashAlg) {
        X509Certificate receiverCert = CertificationAuthority.retrieveCertificate(receiverUsername);
        CertificationAuthority.IsValidCertificate(receiverCert);

        int size = 128;
        if (algorithm.contains("DESede")) {
            size = 168;
        } else if (algorithm.contains("DES")) {
            size = 56;
        }

        String folderName = Base64.getEncoder().encodeToString(CodeSecurity.HashAlgorithm(receiverUsername, "SHA-512"));
        folderName = folderName.replace(File.separatorChar, 'a');
        folderName = folderName.replace('/', 'a');

        try (PrintWriter cryptedFile = new PrintWriter(new File(CodeProtection.parent.getPath() + File.separatorChar + folderName
                + File.separatorChar + folderName.substring(0, 10) + new Random().nextInt(99999) + "crypted.dat"));
                BufferedReader inputFile = new BufferedReader(new FileReader(file))) {
            KeyGenerator keyGen = KeyGenerator.getInstance(algorithm);
            keyGen.init(size);
            SecretKey secretKey = keyGen.generateKey();

            String plainHeader = file.getPath().substring(file.getPath().lastIndexOf(File.separatorChar) + 1) + "::" + CodeProtection.loggedUser.username + "::" + algorithm + "::" + hashAlg + "::" + Base64.getEncoder().encodeToString(secretKey.getEncoded());
            Cipher cipher = Cipher.getInstance("RSA");
            byte[] plainHeaderBytes = plainHeader.getBytes("UTF8");
            cipher.init(Cipher.ENCRYPT_MODE, receiverCert.getPublicKey());
            byte[] cipherHeader = cipher.doFinal(plainHeaderBytes);

            cryptedFile.println(Base64.getEncoder().encodeToString(cipherHeader));

            String code = "", line;
            while ((line = inputFile.readLine()) != null) {
                code += line + System.getProperty("line.separator");
            }

            cryptedFile.println(EncryptionAlgorithm(code, algorithm, secretKey));
            cryptedFile.println("=============================================");

            byte[] hash = HashAlgorithm(plainHeader + code, hashAlg);
            cipher.init(Cipher.ENCRYPT_MODE, CodeProtection.loggedUser.keyPair.getPrivate());
            byte[] signedHash = cipher.doFinal(hash);

            cryptedFile.println(Base64.getEncoder().encodeToString(signedHash));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static boolean DecryptFile(File file, String messageSender) {
        X509Certificate senderCert = CertificationAuthority.retrieveCertificate(messageSender);
        CertificationAuthority.IsValidCertificate(senderCert);

        File newFile = new File(CodeProtection.loggedUser.userFolder.getPath() + File.separatorChar + new Random().nextInt(99999) + "decrypted.java");
        try (PrintWriter decryptedFile = new PrintWriter(newFile);
                BufferedReader inputFile = new BufferedReader(new FileReader(file))) {
            String cryptedHeader = inputFile.readLine();
            Cipher cipher = Cipher.getInstance("RSA");
            byte[] headerBytes = Base64.getDecoder().decode(cryptedHeader);
            cipher.init(Cipher.DECRYPT_MODE, CodeProtection.loggedUser.keyPair.getPrivate());
            byte[] plainHeaderBytes = cipher.doFinal(headerBytes);
            String plainHeader = new String(plainHeaderBytes, "UTF8");

            String[] info = plainHeader.split("::");
            if (info.length != 5) {
                return closeAndAlert(newFile, decryptedFile);
            }

            String cipherCode = "", lineOfCipherCode;
            while (!(lineOfCipherCode = inputFile.readLine()).contains("==============")) {
                cipherCode += lineOfCipherCode;
            }

            byte[] secretKeyBytes = Base64.getDecoder().decode(info[4]);
            SecretKey secretKey = new SecretKeySpec(secretKeyBytes, 0, secretKeyBytes.length, info[2]);
            String code = DecryptionAlgorithm(cipherCode, info[2], secretKey);
            decryptedFile.println(code);

            String signedHash = inputFile.readLine();
            byte[] signedHashDecoded = Base64.getDecoder().decode(signedHash);
            cipher.init(Cipher.DECRYPT_MODE, senderCert.getPublicKey());
            byte[] hashDecrypted = cipher.doFinal(signedHashDecoded);
            String hashDecryptedString = new String(hashDecrypted, "UTF8");

            byte[] calculatedHash = HashAlgorithm(plainHeader + code, info[3]);
            String calculatedHashString = new String(calculatedHash, "UTF8");

            if (!info[1].equals(messageSender) || !hashDecryptedString.equals(calculatedHashString)) {
                return closeAndAlert(newFile, decryptedFile);
            }
            File newFileName = new File(CodeProtection.loggedUser.userFolder.getPath() + File.separatorChar + info[0]);
            decryptedFile.close();
            Files.move(newFile.toPath(), newFileName.toPath(), REPLACE_EXISTING);

            runProcess("javac -Xlint:unchecked -classpath \"" + newFileName.getPath().substring(0, newFileName.getPath().lastIndexOf(File.separatorChar)) + "\" \"" + newFileName.getPath() + "\"");
            runProcess("java -classpath \"" + newFileName.getPath().substring(0, newFileName.getPath().lastIndexOf(File.separatorChar)) + "\" \"" + newFileName.getPath().substring(newFileName.getPath().lastIndexOf(File.separatorChar) + 1).replace(".java", "") + "\"");
            
            
        } catch (Exception e) {
            e.printStackTrace();
            try{
                return closeAndAlert(newFile,null);
            }
            catch(Exception ex){ return false; }
        }

        return true;
    }

    private static boolean closeAndAlert(File newFile, PrintWriter decryptedFile) throws Exception {
        Alert alert = new Alert(Alert.AlertType.ERROR, "Message is corrupted or is not sent to you" + " !", ButtonType.OK);
        alert.showAndWait();
        decryptedFile.close();
        Files.deleteIfExists(newFile.toPath());
        return false;
    }

    private static void printLines(String name, InputStream ins) throws Exception 
    {
        String line = null,result=name;
        BufferedReader in = new BufferedReader(new InputStreamReader(ins));
        while ((line = in.readLine()) != null) 
            result+=line+System.getProperty("line.separator");

        if(result.length()>name.length())
        {
            Label stdOut=new Label(result);
            stdOut.setStyle("-fx-font-size:16;-fx-text-fill:white");
            stdOut.setAlignment(Pos.CENTER);
            BorderPane borderPane=new BorderPane();
            borderPane.setCenter(stdOut);
            borderPane.setStyle("-fx-background-color:DARKGRAY");
            Stage stage=new Stage();
            stage.setScene(new Scene(borderPane,480,320));
            stage.setTitle("Output of decrypted source code");
            stage.showAndWait();
        }
    }

    private static void runProcess(String command) throws Exception {
        Process pro = Runtime.getRuntime().exec(command);
        printLines("stdout: ", pro.getInputStream());
    }
}
