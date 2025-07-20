#include <iostream>
#include <fstream>
#include <tuple>

using namespace std;

struct Point {
    long long x, y;
};

const long long a = 2;   // Elliptic curve parameter a
const long long b = 3;   // Elliptic curve parameter b
const long long p = 97;  // Prime field GF(p)

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

// Scalar multiplication: k * P using double-and-add
Point scalarMult(long long k, Point P) {
    Point result = {0, 0}; // Point at infinity
    Point temp = P;

    while (k > 0) {
        if (k & 1) {
            // Add current point if the lowest bit of k is 1
            result = (result.x == 0 && result.y == 0) ? temp : pointAdd(result, temp);
        }
        // Double the point
        temp = pointAdd(temp, temp);
        k >>= 1; // Right shift k by 1 (divide by 2)
    }

    return result;
}

void bobComputeSharedSecret() {
    // Load Bob's private key
    long long d;
    ifstream privateFile("bob_private.txt");
    if (!privateFile) {
        cerr << "Error reading bob_private.txt\n";
        return;
    }

    // Read the line and extract the private key
    string line1;
    getline(privateFile, line1);
    
    // The private key is after "Private Key d: ", so we parse it
    sscanf(line1.c_str(), "Private Key d: %lld", &d);

    // Load Alice's public key C1
    Point C1;
    ifstream publicFile("alice_public.txt");
    if (!publicFile) {
        cerr << "Error reading alice_public.txt\n";
        return;
    }
    string line;
    getline(publicFile, line);
    sscanf(line.c_str(), "Public Key C1(x, y): (%lld, %lld)", &C1.x, &C1.y);

    // Compute the shared secret: S = d * C1
    Point sharedSecret = scalarMult(d, C1);

    // Save shared secret to file
    ofstream secretFile("shared_secret_bob.txt");
    secretFile << "Shared Secret S(x, y): (" << sharedSecret.x << ", " << sharedSecret.y << ")\n";
    secretFile.close();

    cout<<"Bob: "<<endl;
    cout<<"Private Key d: " << d << "\n";
    cout<<"alice public key (x1, y1): (" << C1.x << ", " << C1.y << ")\n";
    cout<<"shared secreate (x2, y2): (" << sharedSecret.x << ", " << sharedSecret.y << ")\n";

    // cout << "Shared secret computed by Bob and saved to file.\n";
}

int main() {
    bobComputeSharedSecret();
    return 0;
}
