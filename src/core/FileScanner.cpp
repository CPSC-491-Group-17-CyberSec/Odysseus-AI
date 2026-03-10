#include "../ui/MainWindow/MainWindow.h"
#include "../ui/ThreatCard/ThreatCard.h"
#include <iostream>

// think we only include functions in here and API calls to ThreatCard to create cards and MainWindow calls these if bad file found.

void FileScan(const std::filesystem::path &p)
{
	try {
		for (const auto& entry : std::filesystem::directory_iterator(p))
		{
			const std::string filename_str = entry.path().filename().string();

			if (entry.is_directory())
			{
				std::cout << " Dir: " << filename_str << "\\n";
			}
			else if (entry.is_regular_file())
			{
				std::cout << " File: " << filename_str << "\\n";
			}
			else
			{
				std::cout << " Other " << filename_str << "\\n";
			}
		}
	}
	catch (const std::filesystem::filesystem_error& e)
	{
		std::cerr << "Error accessing directory: " << e.what() << "\\n";
	}
}

