package org.logstashplugins;

import co.elastic.logstash.api.*;
import org.apache.commons.lang3.StringUtils;

import java.util.ArrayList;
import java.util.Collection;

// class name must match plugin name
@LogstashPlugin(name = "java_filter_example")
public class JavaFilterExample implements Filter {

    public static final PluginConfigSpec<String> SOURCE_CONFIG =
            PluginConfigSpec.stringSetting("source", "source_message");

    public static final PluginConfigSpec<String> TARGET_CONFIG =
            PluginConfigSpec.stringSetting("target", "target_message");


    public static final PluginConfigSpec<String> KEY_FIELD =
            PluginConfigSpec.stringSetting("key", "key123");

    public static final PluginConfigSpec<String> IV_FIELD =
            PluginConfigSpec.stringSetting("iv", "iv123");

    private String id;
    private String sourceField;
    private String keyField;
    private String targetField;
    private String iv;

    public JavaFilterExample(String id, Configuration config, Context context) {
        // constructors should validate configuration options
        this.id = id;
        this.sourceField = config.get(SOURCE_CONFIG);
        this.keyField = config.get(KEY_FIELD);
        this.targetField = config.get(TARGET_CONFIG);
        this.iv = config.get(IV_FIELD);
    }

    @Override
    public Collection<Event> filter(Collection<Event> events, FilterMatchListener matchListener) {
        try {
            for (Event e : events) {
                //System.out.println("##################################################################");
                //System.out.println(SOURCE_CONFIG);
                //System.out.println(e);

               /* e.getData().keySet().forEach((key) -> {
                  *//*  System.out.println(key);
                    if (key.equals("userId")){
                        System.out.println("userId exist");
                    }
                });
                System.out.println("\n \n ############################# " + sourceField + " ############################# \n \n");
                System.out.println("\n \n ############################# " + sourceField.equals("userId") + " ############################# \n \n");
                System.out.println("\n \n ############################# " +  e.getData().containsKey(sourceField) + " ############################# \n \n");
                System.out.println("\n \n ############################# " + e.getData().containsKey("userId") + " ############################# \n \n");*/
                Object f = e.getField(sourceField);

                //System.out.println(f.toString());
                String encrypted_text = AES.encrypt((String) f, keyField, iv, false);
                if (f != null) {
                    e.setField(sourceField, f);
                    e.setField(targetField, encrypted_text);
                    matchListener.filterMatched(e);

                }
                if (f == null) {
                    throw new Exception("########### Incorrect Source Field ##########");
                }
            }
            return events;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public Collection<PluginConfigSpec<?>> configSchema() {
        // should return a list of all configuration options for this plugin
        Collection<PluginConfigSpec<?>> col = new ArrayList<>();
        col.add(SOURCE_CONFIG);
        col.add(TARGET_CONFIG);
        col.add(KEY_FIELD);
        col.add(IV_FIELD);
        return col;
    }

    @Override
    public String getId() {
        return this.id;
    }

}