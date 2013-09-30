import sun.misc.BASE64Encoder;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.Scanner;
import java.util.TreeMap;


class MessageCreator{
    String oauthTokenSecret = "";
    String url;
    TreeMap <String, String> arguments = new TreeMap<String, String>();

    public MessageCreator(String url_string){
        url=url_string;
    }
    public MessageCreator withArg(String arg, String val){
        arguments.put(arg, val);
        return this;
    }

    public String getEncodedMess(){
        String strUrl=url;
        String startsArgs = argsToString();
        if (oauthTokenSecret.length()>0){  //Exchanging the Request Token for an Access Token - need new signature
            startsArgs = delParamFromArgsString(argsToString(), "oauth_callback");
            startsArgs = delParamFromArgsString(startsArgs,"oauth_signature");
            strUrl= "http://www.flickr.com/services/oauth/access_token";
        }

        String res = null;
        try {
            res = "GET&"+ URLEncoder.encode(strUrl, "UTF-8")+"&"+ URLEncoder.encode(startsArgs, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            e.toString();
        }
        System.out.println("enc: "+res);
        return res;

    }

    private String argsToString() {
        StringBuilder sb = new StringBuilder();
        String divider = "";
        for(Map.Entry<String, String> e : arguments.entrySet()){
            sb.append(divider);
            divider = "&";
            sb.append(e.getKey()).append("=").append(e.getValue());
        }
        return sb.toString();
    }

    private String requestGET(String address) {
        System.out.println("address:"+address);

        String result="";
        try {
            URL url = new URL(address);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();

            conn.setRequestProperty("User-Agent", "Java bot");

            conn.connect();

            int code=conn.getResponseCode();
            System.out.println("code="+code);
            if (code==200) {
                BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()));

                String inputLine;

                while ((inputLine = in.readLine()) != null) {
                    result+=inputLine;
                }
                in.close();
            }

            conn.disconnect();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return result;
    }

   public String getRequestToken(){
       String address = url+"?"+argsToString();
       String result = requestGET(address);
       fillOAuthTokens(result);
       return result;
   }

   public void getUserAuthorization(){
       String address = "http://www.flickr.com/services/oauth/authorize?oauth_token="+arguments.get("oauth_token");

       try {
           java.awt.Desktop.getDesktop().browse(java.net.URI.create(address));
       } catch (java.io.IOException e) {
           System.out.println(e.getMessage());
       }
   }
   private String delParamFromArgsString(String base, String par){
       String [] mas = base.split(par+"="+arguments.get(par));
       if (mas[1].startsWith("&"))
               return mas[0]+mas[1].substring(1);
       return mas[0];
   }
   public void getRequestTokenForAnAccessToken(){
       String address = "http://www.flickr.com/services/oauth/access_token?"+
               delParamFromArgsString(argsToString(), "oauth_callback");
       String result = requestGET(address);
       System.out.println(result);
   }

   private void fillOAuthTokens(String req){
        String [] params = req.split("&");
        if ("oauth_callback_confirmed=true".equals(params[0])){
            withArg("oauth_token", params[1].split("=")[1]);
            oauthTokenSecret = params[2].split("=")[1];
        }
        System.out.println("oauthTokenSecret="+oauthTokenSecret);
    }

}

public class FlickrerMain {

    private static String fileName = "conf.txt";
    private static MessageCreator msg;

    private static boolean isAppOAuthInConf(){
        boolean isAppOAuth = false;
        try {
            BufferedReader in = new BufferedReader(new FileReader(fileName));
            String str;
            while (((str = in.readLine()) != null) && (!isAppOAuth)){
                if(str.startsWith("oauth_signature"))
                    isAppOAuth = true;
            }
        } catch (IOException e) {
            System.out.println(e.toString());
        }
        return isAppOAuth;
    }

    private static void setArgsFromConf(){
        try {
            BufferedReader in = new BufferedReader(new FileReader(fileName));
            String str;

            while ((str = in.readLine()) != null){
                if (!str.startsWith("!"))
                    msg.withArg(str.split(":")[0], str.split(":")[1]);
                else{
                    if (str.startsWith("!oauth_token_secret"))
                      msg.oauthTokenSecret = str.split(":")[1];
                }
            }
        } catch (IOException e) {
            System.out.println(e.toString());
        }
    }

    private static void writeParam(FileWriter out, String paramName, String paramVal) throws IOException {
            out.write(paramName+":"+paramVal+"\n");
    }

    private static void writeParams() {
        try {
            FileWriter out = new FileWriter(fileName,false);
            for (Map.Entry<String, String> p : msg.arguments.entrySet()){
                writeParam(out, p.getKey(), p.getValue());
            }
            writeParam(out, "!oauth_token_secret", msg.oauthTokenSecret);
            out.close();
        } catch(IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static String getSignature(String secret) throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeyException {
        String mess = msg.getEncodedMess();
        SecretKeySpec keySpec = new SecretKeySpec(
                secret.getBytes("UTF-8"),
                "HmacSHA1");

        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(keySpec);

        BASE64Encoder encoder = new BASE64Encoder();
        String signature = encoder.encode(mac.doFinal(mess.getBytes("UTF-8"))).trim();

        return signature;
    }
    public static void main(String[] args) throws UnsupportedEncodingException, InvalidKeyException, NoSuchAlgorithmException {
        String secret = "7a56cd422aea162b&";
        msg = new MessageCreator("http://www.flickr.com/services/oauth/request_token");
        if(!isAppOAuthInConf()){
            msg.withArg("oauth_nonce", "89601180").
                withArg("oauth_timestamp", String.valueOf(System.currentTimeMillis() / 1000)).
                withArg("oauth_consumer_key", "4f4643ac9498da767782ad2d86c28a94").
                withArg("oauth_signature_method", "HMAC-SHA1").
                withArg("oauth_version", "1.0").
                withArg("oauth_callback", "oob");

            msg.withArg("oauth_signature", getSignature(secret));
            System.out.println("oauth_signature = " + msg.arguments.get("oauth_signature"));

            System.out.println(msg.getRequestToken());
            msg.getUserAuthorization();
            Scanner s = new Scanner(System.in);
            System.out.println("Input oauth_verifier");
            msg.withArg("oauth_verifier", s.nextLine());
            writeParams();

        }else{
            setArgsFromConf();
        }
        System.out.println("secret: "+secret+msg.oauthTokenSecret);
        msg.withArg("oauth_signature", getSignature(secret+msg.oauthTokenSecret));
        System.out.println("oauth_signature = " + msg.arguments.get("oauth_signature"));
        msg.getRequestTokenForAnAccessToken();
    }
}