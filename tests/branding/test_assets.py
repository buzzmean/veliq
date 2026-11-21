import hashlib,json,pathlib,re,unittest,xml.etree.ElementTree as ET
ROOT=pathlib.Path(__file__).resolve().parents[2]
class ApprovedBrand(unittest.TestCase):
 def test_exact_approved_assets_and_no_external_content(self):
  manifest=json.loads((ROOT/'assets/brand/SOURCES.json').read_text());self.assertEqual(manifest['source_commit'],'2dfdb483e15abf7a0714347c973647b2c38b31f1');self.assertEqual(len(manifest['files']),4)
  for name,digest in manifest['files'].items():
   p=ROOT/'assets/brand'/name;self.assertEqual(hashlib.sha256(p.read_bytes()).hexdigest(),digest)
   xml=ET.fromstring(p.read_bytes());self.assertEqual(xml.attrib['aria-label'],'VELIQ')
   for e in xml.iter():self.assertNotIn(e.tag.split('}')[-1],('script','image','foreignObject','use'))
 def test_wpf_paths_are_approved_geometry(self):
  svg=ET.parse(ROOT/'assets/brand/veliq3-symbol-reverse.svg');xaml=(ROOT/'apps/desktop/Assets/VeliqBrand.xaml').read_text()
  for e in svg.iter():
   if e.tag.endswith('path'):self.assertIn(e.attrib['d'],xaml)
  ET.fromstring(xaml);self.assertIn('#F0502A',xaml)
 def test_user_strings_and_compatibility(self):
  for e in ET.parse(ROOT/'apps/desktop-core/Resources/Strings.resx').iter('value'):self.assertNotRegex(e.text or '',re.compile(r'neexitlag',re.I))
  project=(ROOT/'apps/desktop/Neexitlag.Desktop.csproj').read_text();self.assertIn('<AssemblyName>VELIQ</AssemblyName>',project);self.assertIn('Assets/VELIQ.ico',project)
  install=(ROOT/'tools/windows/install.ps1').read_text();self.assertIn('New-Service -Name VELIQ',install)
