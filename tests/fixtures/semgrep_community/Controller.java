import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.xml.sax.XMLReader;
import org.xml.sax.helpers.XMLReaderFactory;
import javax.xml.XMLConstants;

@RestController
class Controller {
    @GetMapping("/java/xml")
    public void xml(String input) throws Exception {
        XMLReader reader = XMLReaderFactory.createXMLReader();
        reader.parse(input);
    }

    @GetMapping("/java/safe")
    public void safe(String input) throws Exception {
        XMLReader reader = XMLReaderFactory.createXMLReader();
        reader.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        reader.parse(input);
    }

    void unusedDatabase() throws Exception {
        java.sql.DriverManager.getConnection("jdbc:postgresql:db", "app", "hardcoded-password");
    }
}
