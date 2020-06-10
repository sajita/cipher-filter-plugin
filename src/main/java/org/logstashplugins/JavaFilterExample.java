package org.logstashplugins;

import co.elastic.logstash.api.*;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;

// class name must match plugin name
@LogstashPlugin(name = "java_filter_example")
public class JavaFilterExample implements Filter {

    public static final PluginConfigSpec<String> SOURCE_CONFIG =
            PluginConfigSpec.stringSetting("source", "from_host");
    public static final PluginConfigSpec<String> SOURCE_CONFIG1 =
            PluginConfigSpec.stringSetting("source", "from_host_encrypted");
    public static final PluginConfigSpec<String> SOURCE_CONFIG2 =
            PluginConfigSpec.stringSetting("source", "from_host_decrypted");


    private String id;
    private String sourceField;
    private String sourceField1;
    private String sourceField2;

    public JavaFilterExample(String id, Configuration config, Context context) {
        // constructors should validate configuration options
        this.id = id;
        this.sourceField = config.get(SOURCE_CONFIG);
        this.sourceField1 = config.get(SOURCE_CONFIG1);
        this.sourceField2 = config.get(SOURCE_CONFIG2);
    }

    @Override
 /* public Collection<Event> filter(Collection<Event> events, FilterMatchListener matchListener) {
        for (Event e : events) {
            Object f = e.getField(sourceField1);
            if (f instanceof String) {
                try {
                    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                    SecretKeySpec key = new SecretKeySpec("12345678901234567890123456789012".getBytes(), "AES");
                    cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec("1234567890123456".getBytes()));
                    e.setField(sourceField1, cipher.doFinal(((String) f).getBytes()).toString());
                    matchListener.filterMatched(e);

                } catch (Exception e1) {
                    e1.printStackTrace();
                }
            }
        }
         return events;*/

    public Collection<Event> filter(Collection<Event> events, FilterMatchListener matchListener) {
        for (Event e : events) {
            Object f = e.getField(sourceField);
            //Object f1 = e.getField((sourceField1));
           // Object f2 = e.getField((sourceField2));
            if (f instanceof String) {
                try {
                    // byte[] data= IVDemo.encrypt(f.toString(),"26-ByteSharedKey".getBytes());
                    //String decrypt_data = IVDemo.decrypt(data,"26-ByteSharedKey".getBytes());

                   /* Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                    Cipher cipher1 = Cipher.getInstance("AES/CBC/PKCS5Padding");
                    SecretKeySpec key = new SecretKeySpec("12345678901234567890123456789012".getBytes(), "AES");
                    cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec("1234567890123456".getBytes()));
                    cipher1.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec("1234567890123456".getBytes()));*/
                    //StringBuilder sb = new StringBuilder();
                    //for (int i=0; i<data.length; i++) sb.append(new Integer(data[i]));

                    //e.setField(sourceField1, Arrays.toString(data));
                    //e.setField(sourceField, decrypt_data);
                    //AES aes = new AES();
                    //String a =   AES.encrypt((String) f, "12345678901234567890123456789012") ;
                    String data =   AES.encrypt((String) f, "12345678901234567890123456789012") ;
                    //e.setField(sourceField1, a);
                    e.setField(sourceField2, AES.decrypt(data,"12345678901234567890123456789012"));
                    e.setField(sourceField1, data);
                    matchListener.filterMatched(e);

                } catch (Exception e1) {
                    e1.printStackTrace();
                }
            }
        }

        return events;
    }

    @Override
    public Collection<PluginConfigSpec<?>> configSchema() {
        // should return a list of all configuration options for this plugin
        return Collections.singletonList(SOURCE_CONFIG1);

    }

    @Override
    public String getId() {
        return this.id;
    }
}
