package com.shubhada.twofactorauthentication.tfa;

import dev.samstevens.totp.code.*;
import dev.samstevens.totp.exceptions.QrGenerationException;
import dev.samstevens.totp.qr.QrData;
import dev.samstevens.totp.qr.QrGenerator;
import dev.samstevens.totp.qr.ZxingPngQrGenerator;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;
import dev.samstevens.totp.util.Utils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class TwoFactorAuthenticationService {
    //generate secret token

    public String generateNewSecret()
    {
        return new  DefaultSecretGenerator().generate();
    }
    //get or to generate QR code Image URI
    public String generateQrCodeImageUri(String secret)
    {

        QrData data=new QrData.Builder()
                .label("Two Factor Authentication")
                .secret(secret)
                .issuer("shubhada-raut")
                .algorithm(HashingAlgorithm.SHA1)
                .digits(6)
                .period(30)   //how long this code should be valid -> 30 sec
                .build();
        QrGenerator generator= new ZxingPngQrGenerator();
        byte[] imageData=new byte[0];
        try
        {
            imageData=generator.generate(data);
        } catch (QrGenerationException e) {
            e.printStackTrace();
            log.error("Error while generating QR code");
        }
        return Utils.getDataUriForImage(imageData,generator.getImageMimeType());
    }
    //to validate code itself

    public boolean isOtpValid(String secret, String code)
    {
        TimeProvider timeProvider=new SystemTimeProvider();
        CodeGenerator codeGenerator=new DefaultCodeGenerator();
        //verifies our code
        CodeVerifier verifier=new DefaultCodeVerifier(codeGenerator,timeProvider);
        return verifier.isValidCode(secret,code);
    }

    public boolean isOtpNotValid(String secret,String code)
    {
        return !this.isOtpValid(secret,code);
    }

}
