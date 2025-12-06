import java.math.BigInteger;

/**
 * Arithmetic on Edwards elliptic curves.
 * Implements the NUMS ed-256-mers* curve for 128-bit security level.
 *
 * Curve equation: x^2 + y^2 = 1 + d*x^2*y^2 mod p
 * where p = 2^256 - 189
 *       d = 15343
 *
 * TCSS 487 Cryptography Project Part 2.
 *
 * @author Balkirat Singh
 * @author Jakita Kaur
 * @version 2.0
 */
public class Edwards {

    // Curve parameters for NUMS ed-256-mers*
    private final BigInteger p;  // Prime field modulus: 2^256 - 189
    private final BigInteger d;  // Curve constant: 15343
    private final BigInteger r;  // Subgroup order
    private final BigInteger n;  // Curve order: n = 4r

    /**
     * Create an instance of the default curve NUMS-256.
     */
    public Edwards() {
        // p = 2^256 - 189
        p = BigInteger.TWO.pow(256).subtract(BigInteger.valueOf(189));

        // d = 15343
        d = BigInteger.valueOf(15343);

        // r = 2^254 - 87175310462106073678594642380840586067
        r = BigInteger.TWO.pow(254).subtract(
            new BigInteger("87175310462106073678594642380840586067")
        );

        // n = 4r
        n = r.multiply(BigInteger.valueOf(4));
    }

    /**
     * Get the prime field modulus.
     * @return p
     */
    public BigInteger getP() {
        return p;
    }

    /**
     * Get the curve constant d.
     * @return d
     */
    public BigInteger getD() {
        return d;
    }

    /**
     * Get the subgroup order r.
     * @return r
     */
    public BigInteger getR() {
        return r;
    }

    /**
     * Get the curve order n.
     * @return n
     */
    public BigInteger getN() {
        return n;
    }

    /**
     * Determine if a given affine coordinate pair P = (x, y)
     * defines a point on the curve.
     *
     * @param x x-coordinate of presumed point on the curve
     * @param y y-coordinate of presumed point on the curve
     * @return whether P is really a point on the curve
     */
    public boolean isPoint(BigInteger x, BigInteger y) {
        // Check: x^2 + y^2 = 1 + d*x^2*y^2 (mod p)

        BigInteger x2 = x.multiply(x).mod(p);
        BigInteger y2 = y.multiply(y).mod(p);

        // Left side: x^2 + y^2
        BigInteger left = x2.add(y2).mod(p);

        // Right side: 1 + d*x^2*y^2
        BigInteger right = BigInteger.ONE.add(
            d.multiply(x2).multiply(y2)
        ).mod(p);

        return left.equals(right);
    }

    /**
     * Find a generator G on the curve with the smallest possible
     * y-coordinate in absolute value.
     *
     * @return G.
     */
    public Point gen() {
        // Generator has y0 = -4 (mod p)
        BigInteger y0 = p.subtract(BigInteger.valueOf(4));

        // Find x0: unique even number satisfying the curve equation
        // x = sqrt[(1 - y^2) / (1 - d*y^2)] mod p

        BigInteger y2 = y0.multiply(y0).mod(p);

        // Numerator: 1 - y^2
        BigInteger numerator = BigInteger.ONE.subtract(y2).mod(p);

        // Denominator: 1 - d*y^2
        BigInteger denominator = BigInteger.ONE.subtract(d.multiply(y2)).mod(p);

        // v = numerator / denominator = numerator * denominator^-1
        BigInteger v = numerator.multiply(denominator.modInverse(p)).mod(p);

        // x0 = sqrt(v) with LSB = 0 (even)
        BigInteger x0 = sqrt(v, p, false);

        if (x0 == null) {
            throw new RuntimeException("Failed to compute generator point");
        }

        return new Point(x0, y0);
    }

    /**
     * Create a point from its y-coordinate and
     * the least significant bit (LSB) of its x-coordinate.
     *
     * @param y the y-coordinate of the desired point
     * @param x_lsb the LSB of its x-coordinate
     * @return point (x, y) if it exists and has order r,
     *         otherwise the neutral element O = (0, 1)
     */
    public Point getPoint(BigInteger y, boolean x_lsb) {
        // Compute x from y and x_lsb
        // x = ±sqrt[(1 - y^2) / (1 - d*y^2)] mod p

        BigInteger y2 = y.multiply(y).mod(p);

        // Numerator: 1 - y^2
        BigInteger numerator = BigInteger.ONE.subtract(y2).mod(p);

        // Denominator: 1 - d*y^2
        BigInteger denominator = BigInteger.ONE.subtract(d.multiply(y2)).mod(p);

        // v = numerator / denominator
        BigInteger v = numerator.multiply(denominator.modInverse(p)).mod(p);

        // Compute square root with specified LSB
        BigInteger x = sqrt(v, p, x_lsb);

        if (x == null) {
            // Point does not exist, return neutral element
            return new Point();
        }

        Point P = new Point(x, y);

        // Verify it's on the curve
        if (!isPoint(x, y)) {
            return new Point();
        }

        // Check if it has order r by verifying r*P = O
        Point rP = P.mul(r);
        if (!rP.isZero()) {
            return new Point();
        }

        return P;
    }

    /**
     * Compute a square root of v mod p with a specified least-significant bit
     * if such a root exists.
     *
     * @param v the radicand.
     * @param p the modulus (must satisfy p mod 4 = 3).
     * @param lsb desired least significant bit (true: 1, false: 0).
     * @return a square root r of v mod p with r mod 2 = 1 iff lsb = true
     *         if such a root exists, otherwise null.
     */
    public static BigInteger sqrt(BigInteger v, BigInteger p, boolean lsb) {
        assert (p.testBit(0) && p.testBit(1)); // p = 3 (mod 4)

        if (v.signum() == 0) {
            return BigInteger.ZERO;
        }

        // r = v^((p+1)/4) mod p
        BigInteger r = v.modPow(p.shiftRight(2).add(BigInteger.ONE), p);

        // Correct the LSB if needed
        if (r.testBit(0) != lsb) {
            r = p.subtract(r);
        }

        // Verify that r^2 = v (mod p)
        return (r.multiply(r).subtract(v).mod(p).signum() == 0) ? r : null;
    }

    /**
     * Display a human-readable representation of this curve.
     *
     * @return a string of form "E: x^2 + y^2 = 1 + d*x^2*y^2 mod p"
     *         where E is a suitable curve name (e.g. NUMS ed-256-mers*),
     *         d is the actual curve equation coefficient defining this curve,
     *         and p is the order of the underlying finite field F_p.
     */
    public String toString() {
        return "NUMS ed-256-mers*: x^2 + y^2 = 1 + " + d + "*x^2*y^2 mod " + p;
    }

    /**
     * Edwards curve point in affine coordinates.
     * NB: this is a nested class, enclosed within the Edwards class.
     */
    public class Point {

        private final BigInteger x;
        private final BigInteger y;

        /**
         * Create a copy of the neutral element on this curve.
         */
        public Point() {
            // Neutral element O = (0, 1)
            this.x = BigInteger.ZERO;
            this.y = BigInteger.ONE;
        }

        /**
         * Create a point from its coordinates (assuming
         * these coordinates really define a point on the curve).
         *
         * @param x the x-coordinate of the desired point
         * @param y the y-coordinate of the desired point
         */
        private Point(BigInteger x, BigInteger y) {
            this.x = x.mod(p);
            this.y = y.mod(p);
        }

        /**
         * Get the x-coordinate of this point.
         * @return x
         */
        public BigInteger getX() {
            return x;
        }

        /**
         * Get the y-coordinate of this point.
         * @return y
         */
        public BigInteger getY() {
            return y;
        }

        /**
         * Determine if this point is the neutral element O on the curve.
         *
         * @return true iff this point is O
         */
        public boolean isZero() {
            return x.equals(BigInteger.ZERO) && y.equals(BigInteger.ONE);
        }

        /**
         * Determine if a given point P stands for
         * the same point on the curve as this.
         *
         * @param P a point (presumably on the same curve as this)
         * @return true iff P stands for the same point as this
         */
        public boolean equals(Point P) {
            return this.x.equals(P.x) && this.y.equals(P.y);
        }

        /**
         * Given a point P = (x, y) on the curve,
         * return its opposite -P = (-x, y).
         *
         * @return -P
         */
        public Point negate() {
            // -P = (-x, y) = (p - x, y)
            return new Point(p.subtract(x), y);
        }

        /**
         * Add two given points on the curve, this and P.
         *
         * @param P a point on the curve
         * @return this + P
         */
        public Point add(Point P) {
            // Edwards addition formula:
            // (x1, y1) + (x2, y2) = (x3, y3) where:
            // x3 = (x1*y2 + y1*x2) / (1 + d*x1*x2*y1*y2) mod p
            // y3 = (y1*y2 - x1*x2) / (1 - d*x1*x2*y1*y2) mod p

            BigInteger x1 = this.x;
            BigInteger y1 = this.y;
            BigInteger x2 = P.x;
            BigInteger y2 = P.y;

            // Common term: d*x1*x2*y1*y2
            BigInteger dxy = d.multiply(x1).multiply(x2).multiply(y1).multiply(y2).mod(p);

            // x3 numerator: x1*y2 + y1*x2
            BigInteger x3num = x1.multiply(y2).add(y1.multiply(x2)).mod(p);

            // x3 denominator: 1 + d*x1*x2*y1*y2
            BigInteger x3den = BigInteger.ONE.add(dxy).mod(p);

            // x3 = x3num / x3den = x3num * x3den^-1
            BigInteger x3 = x3num.multiply(x3den.modInverse(p)).mod(p);

            // y3 numerator: y1*y2 - x1*x2
            BigInteger y3num = y1.multiply(y2).subtract(x1.multiply(x2)).mod(p);

            // y3 denominator: 1 - d*x1*x2*y1*y2
            BigInteger y3den = BigInteger.ONE.subtract(dxy).mod(p);

            // y3 = y3num / y3den = y3num * y3den^-1
            BigInteger y3 = y3num.multiply(y3den.modInverse(p)).mod(p);

            return new Point(x3, y3);
        }

        /**
         * Multiply a point P = (x, y) on the curve by a scalar m.
         *
         * @param m a scalar factor (an integer mod the curve order)
         * @return m*P
         */
        public Point mul(BigInteger m) {
            // Double-and-add algorithm
            Point V = new Point(); // neutral element O

            // Handle negative scalars
            BigInteger scalar = m.mod(n);

            int bitLength = scalar.bitLength();
            for (int i = bitLength - 1; i >= 0; i--) {
                V = V.add(V);  // double
                if (scalar.testBit(i)) {
                    V = V.add(this);  // add if bit is 1
                }
            }

            return V;
        }

        /**
         * Display a human-readable representation of this point.
         *
         * @return a string of form "(x, y)" where x and y are
         *         the coordinates of this point
         */
        public String toString() {
            return "(" + x + ", " + y + ")";
        }
    }
}
