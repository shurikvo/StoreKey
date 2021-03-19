package ru.shurikvo.storekey;

import android.app.AlertDialog;
import android.content.Intent;
import android.os.Build;
import android.os.Bundle;

import com.google.android.material.appbar.CollapsingToolbarLayout;
import com.google.android.material.floatingactionbutton.FloatingActionButton;
import com.google.android.material.snackbar.Snackbar;

import androidx.annotation.RequiresApi;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.view.View;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.TextView;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import ru.shurikvo.utils.ByteMatter;

public class ScrollingActivity extends AppCompatActivity {
    private static final String KEY_LOG = "LOG";
    //private static final String KEY_SET_TRANSFER = "SET_TRANSFER";
    private static final String ANDROID_KEY_STORE = "AndroidKeyStore";

    private String messageInfo = "";
    private ByteMatter byt = new ByteMatter();

    private AlertDialog mDialog;

    byte[] bCipher = {
            0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
            (byte)0x88,(byte)0x99,(byte)0xAA,(byte)0xBB,(byte)0xCC,(byte)0xDD,(byte)0xEE,(byte)0xFF,
            (byte)0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    };
    byte[] bKey = {
            0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4A,0x4B,0x4C,0x4D,0x4E,0x4F,
            0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x57,0x58,0x59,0x5A,0x5B,0x5C,0x5D,0x5E,0x5F
    };
    byte[] bCrypto = {}, iv;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_scrolling);
        Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);
        CollapsingToolbarLayout toolBarLayout = (CollapsingToolbarLayout) findViewById(R.id.toolbar_layout);
        toolBarLayout.setTitle(getTitle());

        FloatingActionButton fab = (FloatingActionButton) findViewById(R.id.fab);
        fab.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                String subject = "NFC Info "+android.text.format.DateFormat.format("yyMMddHHmmss", new java.util.Date()).toString();
                Intent email = new Intent(Intent.ACTION_SEND);
                email.putExtra(Intent.EXTRA_EMAIL, new String[]{ "shurikvo@gmail.com" });
                email.putExtra(Intent.EXTRA_SUBJECT, subject);
                email.putExtra(Intent.EXTRA_TEXT, messageInfo);
                email.setType("message/rfc822");
                startActivity(Intent.createChooser(email, "Choose an Email client :"));
            }
        });

        FloatingActionButton wrk = (FloatingActionButton) findViewById(R.id.wrk);
        wrk.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                doEncrypt();
                doDecrypt();
            }
        });

        FloatingActionButton fin = (FloatingActionButton) findViewById(R.id.fin);
        fin.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                showMessage(R.string.about, R.string.about_text);
            }
        });

        mDialog = new AlertDialog.Builder(this).setNeutralButton("Ok", null).create();

        if (savedInstanceState != null) {
            //transfer = savedInstanceState.getString(KEY_SET_TRANSFER, "");
            messageInfo = savedInstanceState.getString(KEY_LOG, "N");
            showInfo();
        }
    }
    //----------------------------------------------------------------------------------------------
    private void doDecrypt() {
        StringBuilder sb = new StringBuilder();
        KeyStore keyStore = null;
        final KeyStore.SecretKeyEntry secretKeyEntry;
        final SecretKey secretKey;
        final Cipher cipher;
        final GCMParameterSpec spec;
        final IvParameterSpec specA;

        sb.append("---------- Decrypt begins").append('\n');

        String sKeyAlias = "FirstAESKey";
        try {
            keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
            sb.append("--- KeyStore.getInstance").append('\n');
            keyStore.load(null);
            sb.append("--- keyStore.load").append('\n');
            secretKeyEntry = (KeyStore.SecretKeyEntry) keyStore.getEntry(sKeyAlias, null);
            sb.append("--- keyStore.getEntry").append('\n');

            secretKey = secretKeyEntry.getSecretKey();
            sb.append("--- secretKeyEntry.getSecretKey").append('\n');

            cipher = Cipher.getInstance("AES/CBC/NoPadding");
            sb.append("--- Cipher.getInstance").append('\n');
            //spec = new GCMParameterSpec(128, iv);
            //sb.append("--- new GCMParameterSpec").append('\n');
            specA = new IvParameterSpec(iv);
            sb.append("--- new IvParameterSpec").append('\n');
            cipher.init(Cipher.DECRYPT_MODE, secretKey, specA);
            sb.append("--- cipher.init").append('\n');

            final byte[] decodedData = cipher.doFinal(bCrypto);
            sb.append("--- cipher.doFinal").append('\n');

            sb.append("    IV: ").append(byt.toHexString(iv)).append('\n');
            sb.append("Crypto: ").append(byt.toHexString(bCrypto)).append('\n');
            sb.append("Cipher: ").append(byt.toHexString(decodedData)).append('\n');
        } catch (CertificateException e) {
            sb.append(e.getMessage()).append('\n');
            messageInfo += "\n" + sb.toString();
            showInfo();
            return;
        } catch (IOException e) {
            sb.append(e.getMessage()).append('\n');
            messageInfo += "\n" + sb.toString();
            showInfo();
            return;
        } catch (NoSuchAlgorithmException e) {
            sb.append(e.getMessage()).append('\n');
            messageInfo += "\n" + sb.toString();
            showInfo();
            return;
        } catch (KeyStoreException e) {
            sb.append(e.getMessage()).append('\n');
            messageInfo += "\n" + sb.toString();
            showInfo();
            return;
        } catch (UnrecoverableEntryException e) {
            sb.append(e.getMessage()).append('\n');
            messageInfo += "\n" + sb.toString();
            showInfo();
            return;
        } catch (NoSuchPaddingException e) {
            sb.append(e.getMessage()).append('\n');
            messageInfo += "\n" + sb.toString();
            showInfo();
            return;
        } catch (InvalidAlgorithmParameterException e) {
            sb.append(e.getMessage()).append('\n');
            messageInfo += "\n" + sb.toString();
            showInfo();
            return;
        } catch (InvalidKeyException e) {
            sb.append(e.getMessage()).append('\n');
            messageInfo += "\n" + sb.toString();
            showInfo();
            return;
        } catch (BadPaddingException e) {
            sb.append(e.getMessage()).append('\n');
            messageInfo += "\n" + sb.toString();
            showInfo();
            return;
        } catch (IllegalBlockSizeException e) {
            sb.append(e.getMessage()).append('\n');
            messageInfo += "\n" + sb.toString();
            showInfo();
            return;
        }

        messageInfo += "\n" + sb.toString();
        showInfo();
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    private void doEncrypt() {
        StringBuilder sb = new StringBuilder();
        final KeyGenerator keyGenerator;
        final KeyGenParameterSpec keyGenParameterSpec;
        final SecretKey secretKey;
        final Cipher cipher;

        sb.append("---------- Encrypt begins").append('\n');

        String sKeyAlias = "FirstAESKey";
        try {
            keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE);
            sb.append("--- KeyGenerator.getInstance").append('\n');

            keyGenParameterSpec = new KeyGenParameterSpec.Builder(sKeyAlias,
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .build();
            sb.append("--- KeyGenParameterSpec...").append('\n');


            keyGenerator.init(keyGenParameterSpec);
            sb.append("--- keyGenerator.init").append('\n');

            secretKey = keyGenerator.generateKey();
            sb.append("--- keyGenerator.generateKey").append('\n');

            cipher = Cipher.getInstance("AES/CBC/NoPadding");
            sb.append("--- Cipher.getInstance").append('\n');
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            sb.append("--- cipher.init").append('\n');

            iv = cipher.getIV();
            bCrypto = cipher.doFinal(bCipher);
            sb.append("--- cipher.doFinal").append('\n');


           // sb.append("   Key: ").append(byt.toHexString(bKey)).append('\n');
            sb.append("    IV: ").append(byt.toHexString(iv)).append('\n');
            sb.append("Cipher: ").append(byt.toHexString(bCipher)).append('\n');
            sb.append("Crypto: ").append(byt.toHexString(bCrypto)).append('\n');
        } catch (NoSuchAlgorithmException e) {
            sb.append(e.getMessage()).append('\n');
            messageInfo += "\n" + sb.toString();
            showInfo();
            return;
        } catch (NoSuchProviderException e) {
            sb.append(e.getMessage()).append('\n');
            messageInfo += "\n" + sb.toString();
            showInfo();
            return;
        } catch (InvalidAlgorithmParameterException e) {
            sb.append(e.getMessage()).append('\n');
            messageInfo += "\n" + sb.toString();
            showInfo();
            return;
        } catch (NoSuchPaddingException e) {
            sb.append(e.getMessage()).append('\n');
            messageInfo += "\n" + sb.toString();
            showInfo();
            return;
        } catch (InvalidKeyException e) {
            sb.append(e.getMessage()).append('\n');
            messageInfo += "\n" + sb.toString();
            showInfo();
            return;
        } catch (BadPaddingException e) {
            sb.append(e.getMessage()).append('\n');
            messageInfo += "\n" + sb.toString();
            showInfo();
            return;
        } catch (IllegalBlockSizeException e) {
            sb.append(e.getMessage()).append('\n');
            messageInfo += "\n" + sb.toString();
            showInfo();
            return;
        }

        messageInfo += "\n" + sb.toString();
        showInfo();
    }
    //----------------------------------------------------------------------------------------------
    //----------------------------------------------------------------------------------------------
    //----------------------------------------------------------------------------------------------
    //----------------------------------------------------------------------------------------------
    //----------------------------------------------------------------------------------------------
    //----------------------------------------------------------------------------------------------
    //----------------------------------------------------------------------------------------------
    //----------------------------------------------------------------------------------------------
    @Override
    protected void onSaveInstanceState(Bundle outState) {
        super.onSaveInstanceState(outState);

        //outState.putString(KEY_SET_TRANSFER, transfer);
        outState.putString(KEY_LOG, messageInfo);
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.menu_scrolling, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();

        //noinspection SimplifiableIfStatement
        if (id == R.id.action_settings) {
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    private void showMessage(int title, int message) {
        mDialog.setTitle(title);
        mDialog.setMessage(getText(message));
        mDialog.show();
    }

    public void showInfo() {
        TextView messageText = (TextView) findViewById(R.id.messageText);
        messageText.setText(messageInfo);
    }
    //----------------------------------------------------------------------------------------------
}