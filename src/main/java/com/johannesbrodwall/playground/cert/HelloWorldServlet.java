package com.johannesbrodwall.playground.cert;

import java.io.IOException;
import java.util.Collections;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class HelloWorldServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        System.out.println(Collections.list(req.getAttributeNames()));
        Object attribute = req.getAttribute("javax.servlet.request.X509Certificate");
        resp.getWriter().write("Hello World");
    }

}
