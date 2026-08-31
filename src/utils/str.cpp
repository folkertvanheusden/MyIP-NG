#include <format>
#include <string>
#include <vector>


std::vector<std::string> split(std::string in, const std::string & splitter)
{
        std::vector<std::string> out;
        size_t splitter_size = splitter.size();

        for(;;)
        {
                size_t pos = in.find(splitter);
                if (pos == std::string::npos)
                        break;

                std::string before = in.substr(0, pos);
                out.push_back(before);

                size_t bytes_left = in.size() - (pos + splitter_size);
                if (bytes_left == 0)
                {
                        out.push_back("");
                        return out;
                }

                in = in.substr(pos + splitter_size);
        }

        if (in.size() > 0)
                out.push_back(in);

        return out;
}

std::string dump(const uint8_t *const bytes, const size_t n)
{
	std::string out;
	for(size_t i=0; i<n; i++) {
		const char c = bytes[i];
		out += std::format("{0:c}", char(c > 32 && c < 127 ? c : 32));
	}
	out += "|";
	for(size_t i=0; i<n; i++)
		out += std::format(" {0:02x}", bytes[i]);
	return out;
}
