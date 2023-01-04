/**
 * Created by Liuqi on 2019/4/16.
 */

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.IOException;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class SearchableEncryption {

    private static String nonce = "c59bcf35";
    private static String STREAM_CIPHER_KEY = "thiskeyisverybad";
    private static String ENCRYPTION_KEY = "Sixteen byte key";
    private static String plaintext = "This is uuuuuuuu";
    //private static String plaintext = "This is uuuuuuuuThis is uuuuuuuuThis is uuuuuuuuThis is uuuuuuuuThis is uuuuuuuuThis is uuuuuuuuThis is uuuuuuuuThis is uuuuuuuuThis is uuuuuuuuThis is uuuuuuuuThis is uuuuuuuu";
    private static int L = plaintext.length()*2;
    public static int TIMES=2;

    public static byte[] generateStreamCipher(String key, String nonce, String counter, String target) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key.getBytes(), "AES"), new IvParameterSpec(HexUtil.hexStr2ByteArray(nonce + counter)));
            return cipher.doFinal(target.getBytes("UTF-8"));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static byte[] aesEncrypt(String key, String target, String iv) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            //System.out.println("iv: "+iv.getBytes());
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key.getBytes(), "AES"), new IvParameterSpec(iv.getBytes("UTF-8")));
            return cipher.doFinal(target.getBytes("UTF-8"));
        } catch (Exception e) {
            e.printStackTrace();
        }
        System.out.println("aesEncrypt error!");
        return null;
    }
    public static byte[] aesEncrypt(String key, byte[] target, String iv) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
//            System.out.println("iv: "+iv.getBytes());
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key.getBytes(), "AES"), new IvParameterSpec(iv.getBytes("UTF-8")));
            return cipher.doFinal(target);
        } catch (Exception e) {
            e.printStackTrace();
        }
        System.out.println("aesEncrypt error!");
        return null;
    }
    /**
     * @param keyWordSet 敏感词集
     * @param FileId   文件id
     * @return 索引对象
     * @throws IOException
     */
    public static FileSSEIndex buildIndexFromSet(Set<String> keyWordSet, String FileId) throws IOException {
        //List<String> words = FileUtil.getWordsBySpace(content);
        int count = 0;
        StringBuilder res = new StringBuilder();
        for (String word : keyWordSet) {
            String counter = HexUtil.ljust(24, count, "0");
            int l=counter.length();
            byte[] streamCipher = generateStreamCipher(STREAM_CIPHER_KEY, nonce, counter, plaintext);
            String Si = HexUtil.byteArray2HexStr(streamCipher);

            //编码为base64
            StringBuilder sb = new StringBuilder(Base64Utils.base64Encode(word));

            int sbLen = sb.length();
            for (int i = 0; i < L*TIMES - sbLen; i++) {
                sb.append(".");
            }
            String str = sb.toString();
            //System.out.println("str="+str);
            byte[] Ewibyte = aesEncrypt(ENCRYPTION_KEY, str, plaintext);
            String Ewi = HexUtil.byteArray2HexStr(Ewibyte);
            //System.out.println(Ewi.length()+"Index Ewi:"+Ewi);

            //System.out.println("streamCipher="+streamCipher);
            byte[] FiSibyte = aesEncrypt(ENCRYPTION_KEY, streamCipher, plaintext);
            String FiSi = HexUtil.byteArray2HexStr(FiSibyte);
//            for (int i = 0; i < TIMES; i++) {
//                FiSi+=FiSi;
//            }

            //System.out.println(FiSi.length()+"Index FiSi:"+FiSi);
            //String Ti = Si + FiSi;
            String Ti="";
            for (int i = 0; i < TIMES; i++) {
                Ti+=(Si + FiSi);
            }
            //System.out.println(Ti.length()+"Index Ti:"+Ti);
//            int len1=Ti.length();
//            int len2=Ewi.length();
            char[] result = HexUtil.XOR(Ewi, Ti);
//            for(int i=0;i<result.length;i++){
//                System.out.print(result[i]);
//            }
            //System.out.println(new String(result));
            res.append(new String(result));
            //System.out.println(res.length()+"Index res:"+res);
            count++;
        }
        FileSSEIndex fsl = new FileSSEIndex(FileId, res.toString());
        return fsl;
    }
    /**
     *
     * @param keyword 查询关键词
     * @return 查询陷门
     */
    public static String buildTrapdoor(String keyword){
        //构建陷门
        StringBuilder sb = new StringBuilder(Base64Utils.base64Encode(keyword));
        int sbLen = sb.length();
        //填充到32位以满足AES加密要求
        for (int i = 0; i < L*TIMES - sbLen; i++) {
            sb.append(".");
        }
        String str = sb.toString();
        byte[] cipherKeywordbyte = aesEncrypt(ENCRYPTION_KEY, str, plaintext);
        String trapdoor = HexUtil.byteArray2HexStr(cipherKeywordbyte);
        return trapdoor;
    }
    /**
     *
     * @param trapdoor 查询陷门
     * @param fsi SSE索引数据结构
     * @return 是否包含
     * @throws IOException
     */
    public static boolean searchFromFSI(String trapdoor, FileSSEIndex fsi){
        //搜索
        boolean flag=false;;
        String indexStr=fsi.IndexStr;
        //System.out.println(indexStr.length());
        String[] encWords = FileUtil.getEncWords(indexStr);
        for (String encWord : encWords) {
            char[] TiChar = HexUtil.XOR(trapdoor, encWord);
            String TiStr = new String(TiChar);
//            for (int i = 0; i < TIMES-1; i++) {
//                TiStr+=TiStr;
//            }
            //System.out.println(TiStr.length()+":"+TiStr);
            String[] Ti = new String[2];
            Ti[0] = TiStr.substring(0, TiStr.length() / (2*TIMES));
            Ti[1] = TiStr.substring(TiStr.length()- TiStr.length() / (2*TIMES));

            byte[] ti0 = aesEncrypt(ENCRYPTION_KEY, HexUtil.hexStr2ByteArray(Ti[0]), plaintext);
            String magic = HexUtil.byteArray2HexStr(ti0).toLowerCase();
            if (magic.equals(Ti[1])) {
                flag = true;
                break;
            }
        }
        return flag;
    }
    /**
     * 关键词搜索
     *
     * @param keyword 关键词
     * @throws IOException
     */
    public static void searchFile(String keyword) throws IOException {
        boolean flag;
        File[] files = FileUtil.getDirFiles("enc/");
        StringBuilder sb = new StringBuilder(Base64Utils.base64Encode(keyword));
        int sbLen = sb.length();
        //填充到32位以满足AES加密要求
        for (int i = 0; i < 32 - sbLen; i++) {
            sb.append(".");
        }
        String str = sb.toString();
        byte[] cipherKeywordbyte = aesEncrypt(ENCRYPTION_KEY, str, plaintext);
        String cipher2Search = HexUtil.byteArray2HexStr(cipherKeywordbyte);


        for (File file : files) {
            flag = false;
            String filePath = file.toString();
            String fileName = file.getName();
            String content = FileUtil.read(filePath, "UTF-8");
            String[] encWords = FileUtil.getEncWords(content);
//            System.out.println(encWords);
            for (String encWord : encWords) {
                char[] TiChar = HexUtil.XOR(cipher2Search, encWord);
                String TiStr = new String(TiChar);
                String[] Ti = new String[2];
                Ti[0] = TiStr.substring(0, TiStr.length() / 2);
                Ti[1] = TiStr.substring(TiStr.length() / 2);
                byte[] ti0 = aesEncrypt(ENCRYPTION_KEY, HexUtil.hexStr2ByteArray(Ti[0]), plaintext);
                String magic = HexUtil.byteArray2HexStr(ti0).toLowerCase();
                if (magic.equals(Ti[1])) {
                    flag = true;
                }
            }
            if (flag)
                System.out.println(keyword + " exists in " + fileName);
            else
                System.out.println(keyword + " not exists in " + fileName);
        }
    }
    /**
     *
     * @param trapdoor 查询陷门
     * @return 返回的文件id Set
     */
//    public static Set<String> searchFromDatabase(String trapdoor){
//        System.out.println(trapdoor);
//        Set<String> fileIdSet = new HashSet<>();
//        ConToMysql toMysql = new ConToMysql();
//        String sql = "SELECT * FROM file;";
//        Connection connection = null;
//        try {
//            connection = toMysql.getConnection();
//            Statement statement = connection.createStatement();
//            ResultSet resultSet = statement.executeQuery(sql);
//            while(resultSet.next()){
//                FileSSEIndex interIndex= new FileSSEIndex(resultSet.getString("id"), resultSet.getString("fileindex"));
//                FileSSEIndex interIndex= new FileSSEIndex("123",)
//                if(searchFromFSI(trapdoor,interIndex)){
//                    fileIdSet.add(interIndex.getFileId());
//                }
//            }
//            resultSet.close();
//            statement.close();
//            connection.close();
//        } catch (SQLException throwables) {
//            throwables.printStackTrace();
//        } catch (ClassNotFoundException e) {
//            e.printStackTrace();
//        }
//        return fileIdSet;
//    }
    public static Set<String> searchFromDatabase(String trapdoor,FileSSEIndex interIndex){
        System.out.println(trapdoor);
        Set<String> fileIdSet = new HashSet<>();
//                FileSSEIndex interIndex= new FileSSEIndex(resultSet.getString("id"), resultSet.getString("fileindex"));
//                FileSSEIndex interIndex= new FileSSEIndex("123",)
        if(searchFromFSI(trapdoor,interIndex)){
            fileIdSet.add(interIndex.getFileId());
        }
        return fileIdSet;
    }
    /**
     *
     * @param trapdoor 查询陷门
     * @param list 索引list
     * @return 文件id Set
     */
    public static Set<String> searchFromList(String trapdoor,List<FileSSEIndex> list){
        Set<String> fileIdSet = new HashSet<>();
            for(FileSSEIndex interIndex:list){
                if(searchFromFSI(trapdoor,interIndex)){
                    fileIdSet.add(interIndex.getFileId());
                }
            }
        return fileIdSet;
    }
    public static void doTest()throws IOException, SQLException, ClassNotFoundException{
        //buildIndexFromFile("raw/", "enc/");
        Set<String> set=new HashSet(Arrays.asList("波音787方向舵大部件"));
        //Set<String> set=new HashSet(Arrays.asList("热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热热"));
        String fileId="123";
        FileSSEIndex index=buildIndexFromSet(set,fileId);
        String keyword="波音787方向舵大部件";
        String trapdoor=buildTrapdoor(keyword);
        boolean flag=searchFromFSI(trapdoor,index);
        System.out.println(flag);
    }

    public static void main(String[] args) throws IOException, SQLException, ClassNotFoundException {
        doTest();
    }
}
