package vn.softdreams.hnx.nativehost.digitalsign.xml;

/**
 * Created by chen on 7/14/2017.
 */
public class Dafuq {
    public static void main(String[] args) {
        String path = "C:/dafuq.ex.xml";
        int index = path.lastIndexOf(".");
        String fileName = path.substring(0, index);
        String ext = path.substring(index, path.length());
        System.out.println(fileName + " | " + ext);
    }
}
