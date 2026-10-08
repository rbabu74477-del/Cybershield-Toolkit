import os, sys, tempfile, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import cybershield as cs


class Tests(unittest.TestCase):
    def test_weak_password(self):
        self.assertIn(cs.analyze_password("password")["strength"], ("VERY WEAK", "WEAK"))

    def test_strong_password(self):
        self.assertIn(cs.analyze_password("T7#kLp9!zQw2@xV")["strength"], ("STRONG", "VERY STRONG"))

    def test_generator(self):
        pw = cs.generate_password(20)
        self.assertEqual(len(pw), 20)
        self.assertNotIn(cs.analyze_password(pw)["strength"], ("VERY WEAK", "WEAK"))

    def test_integrity(self):
        with tempfile.TemporaryDirectory() as d:
            open(os.path.join(d, "a.txt"), "w").write("hello")
            old = cs.build_baseline(d)
            open(os.path.join(d, "a.txt"), "w").write("tampered")
            open(os.path.join(d, "b.txt"), "w").write("new")
            r = cs.compare_baseline(old, cs.build_baseline(d))
            self.assertEqual(r["modified"], ["a.txt"])
            self.assertEqual(r["added"], ["b.txt"])

    def test_log(self):
        r = cs.analyze_log(os.path.join(os.path.dirname(__file__), "..", "samples", "auth.log"))
        self.assertEqual(len(r["suspicious"]), 2)
        self.assertEqual(r["suspicious"][0]["ip"], "203.0.113.45")


if __name__ == "__main__":
    unittest.main()
