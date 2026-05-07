import java.io.IOException;
import java.io.InputStream;
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

/**
 * Servlet for importing profile data via XML.
 *
 * Accepts a POST request with an XML body describing profile fields to update.
 *
 * Expected XML format:
 *   <profile>
 *     <bio>Your bio here</bio>
 *   </profile>
 *
 * VULNERABILITY: This servlet parses untrusted XML using a DocumentBuilder
 * with no XXE (XML External Entity) protections enabled. An attacker can
 * supply a crafted DOCTYPE declaration to read arbitrary local files and
 * exfiltrate their contents through the parsed document, e.g.:
 *
 *   <?xml version="1.0" encoding="UTF-8"?>
 *   <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
 *   <profile><bio>&xxe;</bio></profile>
 *
 * @author security-course
 */
public class XmlImportServlet extends HttpServlet {

    /*
     * GET: display a simple form for submitting XML profile data.
     */
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse res) throws IOException {
        HttpSession session = req.getSession(false);
        if (session == null) {
            res.sendRedirect("/welcome");
            return;
        }

        String username = (String) session.getAttribute("username");

        res.setContentType("text/html; charset=utf-8");
        res.setStatus(HttpServletResponse.SC_OK);
        PrintWriter content = res.getWriter();

        content.println("<!DOCTYPE html>");
        content.println("<html lang='en'><head>");
        content.println("<meta charset='UTF-8'>");
        content.println("<title>XML Profile Import</title>");
        content.println("<link rel='stylesheet' type='text/css' href='./Navbar.css'>");
        content.println("</head><body>");

        content.println("<header id='headerNav'>");
        content.println("<div class='header-container'>");
        content.println("<img src='./logo.png' alt='Logo' class='logo' width='150' height='50'>");
        content.println("<span class='hello'>Welcome, " + username + "</span>");
        content.println("<nav class='navbar'>");
        content.println("<a class='nav' href='account'>My Account</a>");
        content.println("<a class='nav' href='transfer'>Transfer</a>");
        content.println("<a class='nav' href='balance'>Customers</a>");
        content.println("<a class='nav' href='xml-import'>XML Import</a>");
        content.println("<form action='logout' method='POST' class='logoutForm'>");
        content.println("<input value='Log Out' type='submit' class='logoutInput nav'>");
        content.println("</form>");
        content.println("</nav></div></header>");

        content.println("<h1>Import Profile via XML</h1>");
        content.println("<p>Paste your XML profile data below and click Import.</p>");
        content.println("<form method='POST' action='xml-import' accept-charset='utf-8'>");
        content.println("<textarea name='xmlData' rows='12' cols='60' style='font-family:monospace'>");
        content.println("&lt;?xml version=\"1.0\" encoding=\"UTF-8\"?&gt;");
        content.println("&lt;profile&gt;");
        content.println("  &lt;bio&gt;Enter your bio here&lt;/bio&gt;");
        content.println("&lt;/profile&gt;");
        content.println("</textarea><br/>");
        content.println("<input type='submit' value='Import'/>");
        content.println("</form>");
        content.println("</body></html>");
    }

    /*
     * POST: parse the submitted XML and update the user's profile bio.
     *
     * VULNERABLE: DocumentBuilder is created without disabling DOCTYPE
     * declarations or external entity resolution, enabling XXE attacks.
     */
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

        if (xmlData == null || xmlData.trim().isEmpty()) {
            out.println("<html><body><p>Error: no XML data provided.</p>");
            out.println("<a href='xml-import'>Go back</a></body></html>");
            return;
        }

        try {
            // VULNERABLE: no XXE protections set on DocumentBuilderFactory
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document doc = db.parse(new InputSource(new StringReader(xmlData)));

            // Extract <bio> text content
            NodeList bioNodes = doc.getElementsByTagName("bio");
            if (bioNodes.getLength() == 0) {
                out.println("<html><body><p>Error: &lt;bio&gt; element not found in XML.</p>");
                out.println("<a href='xml-import'>Go back</a></body></html>");
                return;
            }

            String bio = bioNodes.item(0).getTextContent();

            // Persist the bio to the database
            boolean success = Database.addAccountInfo(username, bio);

            out.println("<html><body>");
            if (success) {
                out.println("<p>Profile updated successfully.</p>");
                out.println("<p><strong>Imported bio:</strong> " + bio + "</p>");
            } else {
                out.println("<p>Failed to update profile.</p>");
            }
            out.println("<a href='account'>View Account</a> | <a href='xml-import'>Import Again</a>");
            out.println("</body></html>");

        } catch (Exception e) {
            out.println("<html><body><p>Error parsing XML: " + e.getMessage() + "</p>");
            out.println("<a href='xml-import'>Go back</a></body></html>");
        }
    }
}
