"""As cópias do supplicant em cada imagem devem ser idênticas à fonte única."""
import os
import unittest

RAIZ = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
FONTE = os.path.join(RAIZ, "autenticador-8021x", "supplicant", "supplicant_8021x.sh")
IMAGENS = ("ubuntu-ied", "oraculo", "atacante", "ids")


class CopiasDoSupplicantTest(unittest.TestCase):
    def test_copias_identicas_a_fonte(self):
        with open(FONTE, "rb") as f:
            esperado = f.read()
        for imagem in IMAGENS:
            with self.subTest(imagem=imagem):
                with open(os.path.join(RAIZ, imagem, "supplicant_8021x.sh"), "rb") as f:
                    self.assertEqual(f.read(), esperado)


if __name__ == "__main__":
    unittest.main()
