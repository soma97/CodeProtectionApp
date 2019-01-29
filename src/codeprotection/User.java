package codeprotection;

import java.io.File;
import java.security.KeyPair;
import java.security.cert.X509Certificate;

public class User {
    String username,password;
    KeyPair keyPair;
    File userFolder;
    X509Certificate userCert;
    
    public User(String username,String password,File folder,X509Certificate userCert)
    {
        this.username=username;
        this.password=password;
        this.keyPair=new KeyPair(userCert.getPublicKey(),CodeProtection.readKey(username,password,folder));
        userFolder=folder;
        this.userCert=userCert;
    }
}
