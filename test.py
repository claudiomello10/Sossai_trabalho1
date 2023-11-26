import unittest
import compare_Passwords


class TestStringMethods(unittest.TestCase):
    def test_compare_passwords(self):
        self.assertTrue(compare_Passwords.main())


if __name__ == "__main__":
    unittest.main()
