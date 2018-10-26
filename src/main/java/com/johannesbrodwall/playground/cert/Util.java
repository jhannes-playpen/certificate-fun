package com.johannesbrodwall.playground.cert;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;

public class Util {

    public static String inputStreamToString(InputStream inputStream) throws IOException {
        try (Reader in = new BufferedReader(new InputStreamReader(inputStream))) {
            StringBuilder result = new StringBuilder();
            int c;
            while ((c = in.read()) != -1) result.append((char)c);
            return result.toString();
        }
    }

}
