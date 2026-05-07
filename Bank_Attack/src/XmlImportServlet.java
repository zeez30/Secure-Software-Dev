import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringReader;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

public class XmlImportServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse res) throws IOException {
        HttpSession session = req.getSession(false);
        if (session == null) {
            res.sendRedirect("/welcome");
            return;
        }

        res.setContentType("text/html; charset=utf-8");
        PrintWriter out = res.getWriter();
        out.println("<html><body>");
        out.println("<h1>XML Profile Import</h1>");
        out.println("<form method='POST' action='xml-import'>");
        out.println("<textarea name='xmlData' rows='10' cols='50'></textarea><br/>");
        out.println("<input type='submit' value='Import'/>");
        out.println("</form></body></html>");
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse res) throws IOException {
        HttpSession session = req.getSession(false);
        if (session == null) {
            res.sendRedirect("/welcome");
            return;
        }

        String username = (String) session.getAttribute("username");
        String xmlData = req.getParameter("xmlData");

        res.setContentType("text/html; charset=utf-8");
        PrintWriter out = res.getWriter();

        try {
            // VULNERABLE: DocumentBuilderFactory has no XXE protections,
            // allowing external entity injection (e.g. reading /etc/passwd).
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document doc = db.parse(new InputSource(new StringReader(xmlData)));

            NodeList bioNodes = doc.getElementsByTagName("bio");
            String bio = bioNodes.item(0).getTextContent();

            Database.addAccountInfo(username, bio);
            out.println("<html><body><p>Profile updated: " + bio + "</p></body></html>");

        } catch (Exception e) {
            out.println("<html><body><p>Error: " + e.getMessage() + "</p></body></html>");
        }
    }
}
