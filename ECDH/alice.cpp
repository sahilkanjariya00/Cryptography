#include <iostream>
#include <fstream>
#include <sstream>

using namespace std;

struct Point {
    long long x, y;
};

// Elliptic curve parameters (same as Bob's)
const long long a = 2;
const long long b = 3;
const long long p = 97;

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
        long long s = (3 * P.x * P.x + a) * modInverse(2 * P.y, p) % p;
        long long xR = (s * s - 2 * P.x) % p;
        long long yR = (s * (P.x - xR) - P.y) % p;
        return { (xR + p) % p, (yR + p) % p };
    } else {
        long long s = (Q.y - P.y) * modInverse(Q.x - P.x, p) % p;
        long long xR = (s * s - P.x - Q.x) % p;
        long long yR = (s * (P.x - xR) - P.y) % p;
        return { (xR + p) % p, (yR + p) % p };
    }
}

Point scalarMult(long long k, Point P) {
    Point R = P;
    k--;
    while (k--) {
        R = pointAdd(R, P);
    }
    return R;
}

void computeSharedSecret() {
    // Load Bob's public key
    Point e1, e2;
    ifstream publicFile("bob_public.txt");
    if (!publicFile) {
        cerr << "Error reading bob_public.txt\n";
        return;
    }
    string line;
    getline(publicFile, line); // Skip curve equation
    getline(publicFile, line);
    sscanf(line.c_str(), "e1(x1, y1): (%lld, %lld)", &e1.x, &e1.y);
    getline(publicFile, line);
    sscanf(line.c_str(), "e2(x2, y2): (%lld, %lld)", &e2.x, &e2.y);

    cout<<"Alice: "<<endl;
    cout<<"e1(x1, y1): (" << e1.x << ", " << e1.y << ")\n";
    cout<<"e2(x2, y2): (" << e2.x << ", " << e2.y << ")\n";

    // Alice's random value r
    long long r = 10;
    Point C1 = scalarMult(r, e1);
    Point C2 = scalarMult(r, e2);

    // Save shared secret to file
    ofstream secretFile("shared_secret.txt");
    secretFile << "Shared Secret C1(x, y): (" << C2.x << ", " << C2.y << ")\n";
    secretFile.close();

    ofstream privateFile("alice_private.txt");
    privateFile << "Private Key r: " << r << "\n";
    privateFile.close();

    // Save Alice's public key to file
    ofstream publicBobFile("alice_public.txt");
    publicBobFile << "Public Key C1(x, y): (" << C1.x << ", " << C1.y << ")\n";
    publicBobFile.close();

    // cout<<"Private Key d: " << d << "\n";
    cout<<"alice public key(x1, y1): (" << C1.x << ", " << C1.y << ")\n";
    cout<<"shared secreat (x2, y2): (" << C2.x << ", " << C2.y << ")\n";

    // cout << "Shared secret computed and saved to file.\n";
}

int main() {
    computeSharedSecret();
    return 0;
}
