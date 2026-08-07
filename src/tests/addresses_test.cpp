#include <cassert>
#include <map>

#include "../utils/addresses.h"


int main(int argc, char *argv[])
{
#if defined(NDEBUG)
	printf("ASSERT IS DISABLED: NOT A DEBUG BUILD\n");
#endif
	addr a0("1.2.3.3", ".", false);
	addr a1("1.2.3.4", ".", false);
	addr a2("1.2.33.4", ".", true);
	addr a3("1.2.51.4", ".", false);
	addr a4("1.2.3.5", ".", false);
	assert(a1 != a2);
	assert(a2 == a3);

	std::map<addr, addr, addr> m1;
	m1.insert({ a1, a1 });
	assert(m1.find(a0) == m1.end());
	assert(m1.find(a4) == m1.end());

	std::map<addr, addr, addr> m2;
	m2.insert({ a0, a0 });
	m2.insert({ a1, a1 });
	assert(m2.find(a0) != m2.end());
	assert(m2.find(a4) == m2.end());

	return 0;
}
