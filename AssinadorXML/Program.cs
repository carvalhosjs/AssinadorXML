using System.Deployment.Internal.CodeSigning;
using System.Runtime.ConstrainedExecution;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;
using static System.Formats.Asn1.AsnWriter;

namespace AssinadorXML
{
    internal class Program
    {
        public static X509Certificate2? CallCertificateStore()
        {
            X509Store store = new X509Store("MY", StoreLocation.CurrentUser);

            try{
                store.Open(OpenFlags.ReadWrite | OpenFlags.OpenExistingOnly);
                store.Open(OpenFlags.ReadWrite | OpenFlags.OpenExistingOnly);
                X509Certificate2Collection collection = (X509Certificate2Collection)store.Certificates;
                X509Certificate2Collection fcollection = (X509Certificate2Collection)collection.Find(X509FindType.FindByTimeValid, DateTime.Now, false);
                X509Certificate2Collection scollection = X509Certificate2UI.SelectFromCollection(fcollection, "Selecione o Certificado", "Selecione o certificado na lista", X509SelectionFlag.MultiSelection);

                if (!scollection[0].HasPrivateKey)
                {
                    return null;
                }
                
                return scollection[0];


    
            }
            catch (ArgumentOutOfRangeException)
            {
                return null;
            }
            catch (CryptographicException) {

                return null;
            }

        }

        public static bool SignXML(X509Certificate2 certificate)
        {
            string path = @"c:\xml\";
            if (!Directory.Exists(path)){
                Directory.CreateDirectory(path);
            }
            string unsigned_file = Path.Combine(path, "unsigned.xml");
            string signed_file = Path.Combine(path,  "signed.xml");


            try
            {
                XmlDocument doc = new XmlDocument();
                doc.Load(new XmlTextReader(unsigned_file));
                SignedXml signedXml = new SignedXml(doc);
                signedXml.SigningKey = certificate.GetRSAPrivateKey();
                signedXml.SignedInfo.SignatureMethod = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
                Reference reference = new Reference();
                reference.Uri = "";
                reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
                //reference.AddTransform(new XmlDsigExcC14NTransform());
                reference.AddTransform(new XmlDsigC14NTransform());
                reference.DigestMethod = "http://www.w3.org/2001/04/xmlenc#sha256";
                signedXml.AddReference(reference);

                KeyInfo info = new KeyInfo();
                KeyInfoX509Data keyInfoX509Data = new KeyInfoX509Data(certificate);
                info.AddClause(keyInfoX509Data);

                signedXml.KeyInfo = info;
                signedXml.ComputeSignature();
                // Get the XML representation of the signature and save
                // it to an XmlElement object.
                XmlElement xmlDigitalSignature = signedXml.GetXml();
                // Append the element to the XML document.
                doc.DocumentElement.AppendChild(doc.ImportNode(xmlDigitalSignature, true));
                if (doc.FirstChild is XmlDeclaration)
                {
                    doc.RemoveChild(doc.FirstChild);
                }

                // Save the signed XML document to a file specified
                // using the passed string.
                using (XmlTextWriter xmltw = new XmlTextWriter(signed_file, new UTF8Encoding(false)))
                {
                    doc.WriteTo(xmltw);
                    xmltw.Close();
                }

                return true;
            }
            catch (Exception)
            {
                return false;
            }

        }


        static void Main(string[] args)
        {
            Console.WriteLine("The file must living in c:\\xml\\unsigned.xml, press any key to continue!");
            Console.ReadLine();
            var cert = CallCertificateStore();
            if (cert != null)
            {
                if (SignXML(cert))
                {
                    Console.WriteLine("Signing...");
                    Console.WriteLine("The file is signed! in c:\\xml\\signed.xml");
                }
                else
                {
                    Console.WriteLine(@"You must provide unsigned.xml inside of c:\xml folder");
                }

            }
        }
    }
}