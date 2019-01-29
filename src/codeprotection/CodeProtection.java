package codeprotection;

import static codeprotection.CertificationAuthority.CASelfSignedCertificate;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import javafx.application.Application;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.VBox;
import javafx.scene.layout.HBox;
import javafx.stage.Stage;
import javafx.scene.control.Label;
import javafx.geometry.Insets;
import javafx.stage.FileChooser;
import javafx.geometry.Pos;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import javafx.scene.control.Alert;
import javafx.scene.control.Alert.AlertType;
import javafx.scene.control.ButtonType;
import javafx.scene.control.ChoiceBox;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextField;
import javafx.scene.image.Image;
import javafx.scene.image.ImageView;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMEncryptor;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaMiscPEMGenerator;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JcePEMEncryptorBuilder;

public class CodeProtection extends Application {
    
    static File users = null;
    public static File parent = new File(System.getProperty("user.home") + File.separatorChar + "Documents" + File.separatorChar + "Code Protection");
    File path = null;
    public static CertificationAuthority certAuthority;
    public static User loggedUser;

    static {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        parent.mkdirs();
        try {
            users = new File(parent.toString() + File.separatorChar + "users.txt");
        } catch (Exception e) {e.printStackTrace();}
        
        certAuthority = new CertificationAuthority();
    }

    public static void main(String[] args) {
        launch(args);
    }

    @Override
    public void start(Stage stage) throws Exception 
    {
        if (!Files.exists(new File(parent.toString() + File.separatorChar + "CA.cer").toPath(), LinkOption.NOFOLLOW_LINKS)) 
        {
            try (FileOutputStream certWriter = new FileOutputStream(new File(parent.toString() + File.separatorChar + "CA.cer"))) {
                certWriter.write(CASelfSignedCertificate.getEncoded());
                certWriter.flush();
                certWriter.close();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        userLogin(stage);
    }

    public void userLogin(Stage stage) {
        Button loginButton = new Button("Login");
        loginButton.setPrefSize(160, 40);
        loginButton.setStyle("-fx-font-size:13");
        Button signUpButton = new Button("Sign up");
        signUpButton.setPrefSize(100, 30);
        signUpButton.setStyle("-fx-font-size:13");

        Label loginLabel = new Label("LOGIN");
        loginLabel.setStyle("-fx-font-size:40;-fx-text-fill:white");
        Label userNameLabel = new Label("Username");
        userNameLabel.setStyle("-fx-font-size:16;-fx-text-fill:white");
        Label passwordLabel = new Label("Password");
        passwordLabel.setStyle("-fx-font-size:16;-fx-text-fill:white");

        ChoiceBox<String> readWriteBox = new ChoiceBox();
        readWriteBox.setStyle("-fx-font-size:13;-fx-text-fill:white");
        readWriteBox.getItems().add("Add source code");
        readWriteBox.getItems().add("Read source code");
        readWriteBox.setValue("Add source code");
        readWriteBox.setPrefSize(160, 30);

        TextField userNameField = new TextField();
        userNameField.setMaxWidth(300);
        userNameField.setStyle("-fx-font-size:14");
        PasswordField passwordField = new PasswordField();
        passwordField.setMaxWidth(300);
        passwordField.setStyle("-fx-font-size:14");

        HBox hBoxBottom = new HBox(15);
        hBoxBottom.setPadding(new Insets(60, 60, 60, 60));
        hBoxBottom.getChildren().addAll(loginLabel);
        hBoxBottom.setAlignment(Pos.TOP_CENTER);
        VBox vBoxCenter = new VBox(20);
        vBoxCenter.setPadding(new Insets(20, 20, 20, 20));
        vBoxCenter.getChildren().addAll(userNameLabel, userNameField, passwordLabel, passwordField, readWriteBox, loginButton);
        vBoxCenter.setAlignment(Pos.TOP_CENTER);
        VBox vBoxBottom = new VBox(15);
        vBoxBottom.setPadding(new Insets(20, 20, 20, 20));
        vBoxBottom.getChildren().addAll(signUpButton);
        vBoxBottom.setAlignment(Pos.CENTER);

        BorderPane layout = new BorderPane();
        layout.setTop(hBoxBottom);
        layout.setCenter(vBoxCenter);
        layout.setLeft(putIcon("icon1.png"));
        layout.setRight(putIcon("icon2.png"));
        layout.setBottom(vBoxBottom);
        layout.setStyle("-fx-background-color:CORNFLOWERBLUE");

        Scene scene = new Scene(layout, 800, 600);
        stage.setTitle("Code Protection App");
        stage.setScene(scene);
        stage.show();

        loginButton.setOnAction(e -> {
            if (checkIdentity(userNameField.getText(), passwordField.getText(),true)) {
                X509Certificate userCert = CertificationAuthority.retrieveCertificate(userNameField.getText());
                try {
                    userCert.checkValidity();
                } 
                catch (CertificateExpiredException | CertificateNotYetValidException exception) 
                {
                    try {
                        certAuthority.writeCRL(certAuthority.generateCRLlist(certAuthority.CASelfSignedCertificate, certAuthority.CAkeyPair.getPrivate(), userCert));
                    } catch (Exception exc) {
                        exc.printStackTrace();
                    }
                    Alert alert = new Alert(AlertType.ERROR, "Certificate has expired" + " !", ButtonType.OK);
                    alert.showAndWait();
                    return;
                }
                try {
                    String folderName = Base64.getEncoder().encodeToString(CodeSecurity.HashAlgorithm(userNameField.getText(),"SHA-512"));
                    folderName = folderName.replace(File.separatorChar, 'a');
                    folderName = folderName.replace('/', 'a');

                    loggedUser = new User(userNameField.getText(), passwordField.getText(), new File(parent.getPath() + File.separatorChar + folderName), userCert);

                    showUI(stage, readWriteBox.getValue());
                } catch (Exception exc) {
                    exc.printStackTrace();
                }
            } else {
                Alert alert = new Alert(AlertType.ERROR, "Incorrect username or password" + " !", ButtonType.OK);
                alert.showAndWait();
            }
        });

        signUpButton.setOnAction(e -> {
            displaySignUp();
        });

    }

    public void showUI(Stage stage, String mode) {
        Button findSourceCodeButton = new Button("Choose source code file");
        findSourceCodeButton.setPrefSize(170, 50);
        Label pathLabel = new Label();
        pathLabel.setStyle("-fx-font-size:16");
        Button cryptButton = new Button("Encrypt");
        cryptButton.setPrefSize(120, 50);
        if (mode.equals("Read source code")) {
            cryptButton.setText("Decrypt");
        }

        ChoiceBox<String> algorithmBox = new ChoiceBox();
        algorithmBox.setStyle("-fx-font-size:13;-fx-text-fill:white");
        algorithmBox.getItems().add("AES");
        algorithmBox.getItems().add("DES");
        algorithmBox.getItems().add("DESede");
        algorithmBox.setValue("AES");
        algorithmBox.setPrefSize(160, 30);
        ChoiceBox<String> hashBox = new ChoiceBox();
        hashBox.setStyle("-fx-font-size:13;-fx-text-fill:white");
        hashBox.getItems().add("SHA-512");
        hashBox.getItems().add("MD5");
        hashBox.setValue("SHA-512");
        hashBox.setPrefSize(160, 30);

        Label otherUserLabel = new Label("Sender username: ");
        otherUserLabel.setStyle("-fx-font-size:16");
        TextField otherUserField = new TextField();

        VBox vBoxBottom = new VBox(15);
        vBoxBottom.setPadding(new Insets(20, 20, 20, 20));
        vBoxBottom.getChildren().addAll(pathLabel, cryptButton);
        vBoxBottom.setAlignment(Pos.TOP_CENTER);
        VBox vBoxCenter = new VBox(25);
        vBoxCenter.setPadding(new Insets(150, 10, 0, 0));
        vBoxCenter.setAlignment(Pos.CENTER);
        
        if (mode.equals("Add source code")) {
            otherUserLabel.setText("Recipient username: ");
            vBoxCenter.getChildren().addAll(findSourceCodeButton, algorithmBox, hashBox, otherUserLabel, otherUserField);
        } else vBoxCenter.getChildren().addAll(findSourceCodeButton, otherUserLabel, otherUserField);

        BorderPane layout = new BorderPane();
        layout.setBottom(vBoxBottom);
        layout.setCenter(vBoxCenter);
        layout.setLeft(putIcon("icon1.png"));
        layout.setRight(putIcon("icon2.png"));
        layout.setStyle("-fx-background-color:CORNFLOWERBLUE");

        Scene scene = new Scene(layout, 800, 600);
        stage.setTitle("Code Protection App");
        stage.setScene(scene);
        stage.show();

        findSourceCodeButton.setOnAction(e -> {
            FileChooser fileChooser = new FileChooser();
            path = fileChooser.showOpenDialog(stage);
            if (path != null) {
                pathLabel.setText(path.toString());
            }
        });

        cryptButton.setOnAction(e -> {
            if (mode.equals("Add source code")) 
            {
                if (checkIdentity(otherUserField.getText(),"",false) && path!=null) 
                {
                    CodeSecurity.EncryptFile(path, otherUserField.getText(), algorithmBox.getValue(), hashBox.getValue());
                    Alert alert = new Alert(AlertType.INFORMATION, "Operation successful" + " !", ButtonType.OK);
                    alert.showAndWait();
                }
                else{
                    Alert alert = new Alert(AlertType.ERROR, "Message receiver does not exist or source code is not selected" + " !", ButtonType.OK);
                    alert.showAndWait();
                }
            } else {
                boolean success=false;
                if (checkIdentity(otherUserField.getText(),"",false) && path!=null)
                    success=CodeSecurity.DecryptFile(path,otherUserField.getText());
                else{
                    Alert alert = new Alert(AlertType.ERROR, "Message sender does not exist or source code is not selected" + " !", ButtonType.OK);
                    alert.showAndWait();
                }
                if(success==false) return;
                Alert alert = new Alert(AlertType.INFORMATION, "Operation successful" + " !", ButtonType.OK);
                alert.showAndWait();
            }
        });
    }

    public void displaySignUp() 
    {
        Button signUpButton = new Button("Sign up");
        signUpButton.setPrefSize(150, 40);
        signUpButton.setStyle("-fx-font-size:14");
        Label userNameLabel = new Label("Username");
        userNameLabel.setStyle("-fx-font-size:16;-fx-text-fill:white");
        Label passwordLabel = new Label("Password");
        passwordLabel.setStyle("-fx-font-size:16;-fx-text-fill:white");

        TextField userNameField = new TextField();
        userNameField.setMaxWidth(300);
        userNameField.setStyle("-fx-font-size:14");
        PasswordField passwordField = new PasswordField();
        passwordField.setMaxWidth(300);
        passwordField.setStyle("-fx-font-size:14");

        VBox vBoxCenter = new VBox(25);
        vBoxCenter.setPadding(new Insets(20, 20, 20, 20));
        vBoxCenter.getChildren().addAll(userNameLabel, userNameField, passwordLabel, passwordField, signUpButton);
        vBoxCenter.setAlignment(Pos.CENTER);

        BorderPane layout = new BorderPane();
        layout.setCenter(vBoxCenter);
        layout.setStyle("-fx-background-color:DARKGRAY");
        Scene scene = new Scene(layout, 480, 320);
        Stage stage = new Stage();
        stage.setTitle("Sign up");
        stage.setScene(scene);
        stage.show();

        signUpButton.setOnAction(e -> {
            addUser(userNameField.getText(), passwordField.getText());
            stage.close();
        });
    }

    public VBox putIcon(String name) {
        try {
            File file = new File(System.getProperty("user.dir") + File.separatorChar + name);
            ImageView icon = new ImageView(new Image(file.toURI().toString()));
            VBox image = new VBox(15);
            image.setPadding(new Insets(20, 20, 20, 20));
            image.getChildren().addAll(icon);
            return image;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public void addUser(String username, String password) {
        try (PrintWriter usersFile = new PrintWriter(new BufferedWriter(new FileWriter(users.toString(), true)))) 
        {
            String folderName = Base64.getEncoder().encodeToString(CodeSecurity.HashAlgorithm(username,"SHA-512"));
            folderName = folderName.replace(File.separatorChar, 'a');
            folderName = folderName.replace('/', 'a');
            File folder = new File(parent.getPath() + File.separatorChar + folderName);
            folder.mkdirs();

            usersFile.println("user:" + username);
            usersFile.println("password:" + Base64.getEncoder().encodeToString(CodeSecurity.HashAlgorithm(password,"SHA-512")));

            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            KeyPair keyPair = keyGen.generateKeyPair();
            X509Certificate userCert = certAuthority.createAndsignCertificate("C=" + username + ",O=CodeProtectionUser", keyPair.getPublic());

            writeKey(username, password, keyPair, folder);

            try (FileOutputStream certWriter = new FileOutputStream(new File(parent.toString() + File.separatorChar + username + ".cer"))) {
                certWriter.write(userCert.getEncoded());
                certWriter.flush();
                certWriter.close();
            } catch (Exception e) {
                e.printStackTrace();
            }

        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    public boolean checkIdentity(String username, String password, boolean requestPassword) {
        try (BufferedReader reader = new BufferedReader(new FileReader(users))) {
            String line = "";
            while ((line = reader.readLine()) != null) 
            {
                if (line.contains("user:")) 
                {
                    line = line.replace("user:", "");
                    if (line.equals(username)) 
                    {
                        if(requestPassword==false) return true;
                        line = reader.readLine();
                        line = line.replace("password:", "");
                        String checkPassword = Base64.getEncoder().encodeToString(CodeSecurity.HashAlgorithm(password,"SHA-512"));
                        if (checkPassword.equals(line))
                            return true;
                    }
                }
            }
        } catch (Exception e) {e.printStackTrace();}
        
        return false;
    }

    public static void writeKey(String username, String password, KeyPair keyPair, File folder) throws FileNotFoundException 
    {
        PrintWriter printKey = new PrintWriter(folder.getPath() + File.separatorChar + "key.pem");
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(printKey)) 
        {
            PEMEncryptor encryptor = new JcePEMEncryptorBuilder("AES-256-CBC").build(password.toCharArray());
            JcaMiscPEMGenerator gen = new JcaMiscPEMGenerator(keyPair.getPrivate(), encryptor);
            pemWriter.writeObject(gen);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static PrivateKey readKey(String username, String password, File folder) {
        //Security.addProvider(new BouncyCastleProvider()); // this is written in static block of this class
        try (PEMParser pemParser = new PEMParser(new FileReader(folder.getPath() + File.separatorChar + "key.pem"))) 
        {
            Object object = pemParser.readObject();
            PEMDecryptorProvider decProv = new JcePEMDecryptorProviderBuilder().build(password.toCharArray());
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider(CertificationAuthority.bcProvider);
            KeyPair keyPair = null;
            if (object instanceof PEMEncryptedKeyPair)
                keyPair = converter.getKeyPair(((PEMEncryptedKeyPair) object).decryptKeyPair(decProv));
            
            return keyPair.getPrivate();
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        return null;
    }

}
