cmake_minimum_required(VERSION 3.20)

project(QtHello)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

find_package(Qt6 REQUIRED COMPONENTS Widgets)

add_executable(main
src/main.cpp
src/ui/ui.cpp
src/ui/MainWindow/MainWindow.cpp
)

target_link_libraries(main
	PRIVATE Qt6::Widgets
)

