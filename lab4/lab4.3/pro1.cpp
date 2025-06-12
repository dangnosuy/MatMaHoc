#include <iostream>
#include <cstdlib>
using namespace std;
extern "C" {
    // 128-byte placeholder, khởi tạo = 0 để đưa vào .data
    unsigned char collision_block[128] = {0};
}
int main() {
    int n;
    cin >> n;
    for (int i = 0; i < n; i++) {
        cout << i << endl;
    }
    return 0;
}