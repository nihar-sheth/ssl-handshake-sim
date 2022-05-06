package coe817project;

public final class RecordLayer {
//    String message = "this is a message";

    public static void main(String[] args) {

        int fragmentSize = 10;
        String message = "yo this is an example message that the client and server would send to eachother";
        String[] temp;
        //String fragment=message.substring(0, fragmentSize);

        temp = fragment(fragmentSize, message);

//        temp[0] = Integer.toString(temp.length -1);
        int count = 0;
        for (String a : temp) {
            System.out.println("count:" + count + " " + a);
            count++;
        }
    }

    public static String[] fragment(int fragSz, String message) {
        int count = 1;
        String fragment = "";
        int start = 0,end = 0;
        int len = message.length();
        int fragmentCount = (int) (len / fragSz) + 2;
        String[] fragments = new String[fragmentCount];
        //UNCOMMENT THIS FOR DEBUGGING OUTPUT--v
//        System.err.println("fragcount: " + fragmentCount);

        for (start = 0, end = fragSz; start < len; start += fragSz, end += fragSz) {
            if (end > len) {
                end = len;
            }
//            System.err.println("start:" + start + "\tend:" + end);
            fragment = message.substring(start,end);
//            System.err.println("fragment:" + fragment);
            fragments[count] = fragment;
 
            count++;
            fragments[count - 1] = fragment;
        }
        fragments[0] = Integer.toString(fragments.length - 1);
        return fragments;
    }
}
