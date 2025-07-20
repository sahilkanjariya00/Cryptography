#include <iostream>
#include <fstream>
#include <tuple>

using namespace std;

struct Point {
    long long x, y;
};

const long long a = 2;  // Elliptic curve parameter a
const long long b = 3;  // Elliptic curve parameter b
const long long p = 97; // Prime field GF(p)
const Point e1 = {3, 6}; // Base point e1 on the curve

// Extended Euclidean Algorithm to find modular inverse
long long modInverse(long long a, long long m) {
    long long m0 = m, t, q;
    long long x0 = 0, x1 = 1;

    if (m == 1)
        return 0;

    while (a > 1) {
        q = a / m;
        t = m;
        m = a % m, a = t;
        t = x0;
        x0 = x1 - q * x0;
        x1 = t;
    }

    if (x1 < 0)
        x1 += m0;

    return x1;
}

// Elliptic curve point addition
Point pointAdd(Point P, Point Q) {
    if (P.x == Q.x && P.y == Q.y) {
        // Point doubling
        long long s = (3 * P.x * P.x + a) * modInverse(2 * P.y, p) % p;
        long long xR = (s * s - 2 * P.x) % p;
        long long yR = (s * (P.x - xR) - P.y) % p;
        return { (xR + p) % p, (yR + p) % p };
    } else {
        // Point addition
        long long s = (Q.y - P.y) * modInverse(Q.x - P.x, p) % p;
        long long xR = (s * s - P.x - Q.x) % p;
        long long yR = (s * (P.x - xR) - P.y) % p;
        return { (xR + p) % p, (yR + p) % p };
    }
}

// Scalar multiplication: k * P
Point scalarMult(long long k, Point P) {
    Point R = P;
    k--;
    while (k--) {
        R = pointAdd(R, P);
    }
    return R;
}

void generateKeys() {
    long long d = 15; // Bob's private key
    Point e2 = scalarMult(d, e1); // Bob's public key e2 = d * e1

    // Save public key to file
    ofstream publicFile("bob_public.txt");
    publicFile << "Elliptic Curve: y^2 = x^3 + " << a << "x + " << b << " over GF(" << p << ")\n";
    publicFile << "e1(x1, y1): (" << e1.x << ", " << e1.y << ")\n";
    publicFile << "e2(x2, y2): (" << e2.x << ", " << e2.y << ")\n";
    publicFile.close();

    // Save private key to file
    ofstream privateFile("bob_private.txt");
    privateFile << "Private Key d: " << d << "\n";
    privateFile.close();

    cout<<"Bob: "<<endl;
    cout<<"Private Key d: " << d << "\n";
    cout<<"e1(x1, y1): (" << e1.x << ", " << e1.y << ")\n";
    cout<<"e2(x2, y2): (" << e2.x << ", " << e2.y << ")\n";

    // cout << "Keys generated and saved to files.\n";
}

int main() {
    generateKeys();
    return 0;
}
