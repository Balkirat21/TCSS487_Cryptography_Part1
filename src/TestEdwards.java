import java.math.BigInteger;

/**
 * Test program for Edwards curve implementation.
 * Validates basic properties required by the specification.
 */
public class TestEdwards {

    public static void main(String[] args) {
        System.out.println("Testing Edwards curve implementation...\n");

        Edwards curve = new Edwards();
        System.out.println("Curve: " + curve);
        System.out.println();

        // Get generator G
        Edwards.Point G = curve.gen();
        System.out.println("Generator G = " + G);
        System.out.println("G.x LSB = " + G.getX().testBit(0));
        System.out.println("Is G on curve? " + curve.isPoint(G.getX(), G.getY()));
        System.out.println();

        // Test 1: 0*G = O (neutral element)
        System.out.println("Test 1: 0*G = O");
        Edwards.Point zeroG = G.mul(BigInteger.ZERO);
        System.out.println("0*G = " + zeroG);
        System.out.println("Is zero? " + zeroG.isZero());
        System.out.println("PASS: " + zeroG.isZero());
        System.out.println();

        // Test 2: 1*G = G
        System.out.println("Test 2: 1*G = G");
        Edwards.Point oneG = G.mul(BigInteger.ONE);
        System.out.println("1*G = " + oneG);
        System.out.println("PASS: " + oneG.equals(G));
        System.out.println();

        // Test 3: G + (-G) = O
        System.out.println("Test 3: G + (-G) = O");
        Edwards.Point negG = G.negate();
        System.out.println("-G = " + negG);
        Edwards.Point sum = G.add(negG);
        System.out.println("G + (-G) = " + sum);
        System.out.println("PASS: " + sum.isZero());
        System.out.println();

        // Test 4: 2*G = G + G
        System.out.println("Test 4: 2*G = G + G");
        Edwards.Point twoG_mul = G.mul(BigInteger.TWO);
        Edwards.Point twoG_add = G.add(G);
        System.out.println("2*G (mul) = " + twoG_mul);
        System.out.println("G+G (add) = " + twoG_add);
        System.out.println("PASS: " + twoG_mul.equals(twoG_add));
        System.out.println();

        // Test 5: 4*G = 2*(2*G)
        System.out.println("Test 5: 4*G = 2*(2*G)");
        Edwards.Point fourG_direct = G.mul(BigInteger.valueOf(4));
        Edwards.Point fourG_double = twoG_mul.mul(BigInteger.TWO);
        System.out.println("4*G (direct) = " + fourG_direct);
        System.out.println("2*(2*G) = " + fourG_double);
        System.out.println("PASS: " + fourG_direct.equals(fourG_double));
        System.out.println();

        // Test 6: 4*G != O
        System.out.println("Test 6: 4*G != O");
        System.out.println("4*G is zero? " + fourG_direct.isZero());
        System.out.println("PASS: " + (!fourG_direct.isZero()));
        System.out.println();

        // Test 7: r*G = O (curve order)
        System.out.println("Test 7: r*G = O (subgroup order)");
        Edwards.Point rG = G.mul(curve.getR());
        System.out.println("r*G is zero? " + rG.isZero());
        System.out.println("PASS: " + rG.isZero());
        System.out.println();

        // Test 8: (k+1)*G = (k*G) + G
        System.out.println("Test 8: (k+1)*G = (k*G) + G");
        BigInteger k = BigInteger.valueOf(12345);
        Edwards.Point kPlusOneG = G.mul(k.add(BigInteger.ONE));
        Edwards.Point kG_plus_G = G.mul(k).add(G);
        System.out.println("PASS: " + kPlusOneG.equals(kG_plus_G));
        System.out.println();

        // Test 9: Test point recovery from y and x_lsb
        System.out.println("Test 9: Point recovery from y and x_lsb");
        BigInteger y = G.getY();
        boolean x_lsb = G.getX().testBit(0);
        Edwards.Point recovered = curve.getPoint(y, x_lsb);
        System.out.println("Original G = " + G);
        System.out.println("Recovered  = " + recovered);
        System.out.println("PASS: " + recovered.equals(G));
        System.out.println();

        // Test 10: Associativity: (k*G) + ((l*G) + (m*G)) = ((k*G) + (l*G)) + (m*G)
        System.out.println("Test 10: Associativity test");
        BigInteger k10 = BigInteger.valueOf(123);
        BigInteger l10 = BigInteger.valueOf(456);
        BigInteger m10 = BigInteger.valueOf(789);
        Edwards.Point left = G.mul(k10).add(G.mul(l10).add(G.mul(m10)));
        Edwards.Point right = G.mul(k10).add(G.mul(l10)).add(G.mul(m10));
        System.out.println("PASS: " + left.equals(right));
        System.out.println();

        System.out.println("All tests completed successfully!");
    }
}
