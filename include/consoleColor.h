//
// Created by Max on 31. 7. 2021.
//

#pragma once
#include <iostream>
#include <string>

enum class colorFG {
    Black = 30,
    Red = 31, //FOREGROUND_RED
    Green = 32, //FOREGROUND_GREEN
    Yellow = 33,
    Blue = 34, //FOREGROUND_BLUE
    Magenta = 35,
    Cyan = 36,
    White = 37,
    Bright_Black = 90,      // FOREGROUND_INTENSITY |
    Bright_Red = 91,        // FOREGROUND_INTENSITY |
    Bright_Green = 92,      // FOREGROUND_INTENSITY |
    Bright_Yellow = 93,     // FOREGROUND_INTENSITY |
    Bright_Blue = 94,       // FOREGROUND_INTENSITY |
    Bright_Magenta = 95,    // FOREGROUND_INTENSITY |
    Bright_Cyan = 96,       // FOREGROUND_INTENSITY |
    Bright_White = 97,      // FOREGROUND_INTENSITY |
    Default = 39

};
enum class  colorBG {
    Black = 40,
    Red = 41,
    Green = 42,
    Yellow = 43,
    Blue = 44,
    Magenta = 45,
    Cyan = 46,
    White = 47,
    Bright_Black = 100,
    Bright_Red = 101,
    Bright_Green = 102,
    Bright_Yellow = 103,
    Bright_Blue = 104,
    Bright_Magenta = 105,
    Bright_Cyan = 106,
    Bright_White = 107,
    Default = 49
};
struct color {
    colorFG fg;
    colorBG bg;
    explicit color(colorFG fgc) {
        fg = fgc;
        bg = colorBG::Default;
    };
    explicit color(colorBG bgc) {
        bg = bgc;
        fg = colorFG::Default;
    };
    color(colorFG fgc, colorBG bgc) : fg(fgc), bg(bgc) {};
    color() : fg(colorFG::Default), bg(colorBG::Default) {};
};

inline std::ostream& operator<<(std::ostream& os, const color& color) {
    std::string str("\033[");
    str += std::to_string(static_cast<int>(color.fg));
    str += ';';
    str += std::to_string(static_cast<int>(color.bg));
    str += 'm';
    os << str;//<<  <<static_cast<int>(color.fg) << ';' << static_cast<int>(color.bg) << 'm';
    return os;
}
inline int setupConsole() {
    std::ios::sync_with_stdio(true);
#ifdef WIN32
    // https://docs.microsoft.com/en-us/windows/console/console-virtual-terminal-sequences#samples
    // Set output mode to handle virtual terminal sequences
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut == INVALID_HANDLE_VALUE)
    {
        return false;
    }
    HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
    if (hIn == INVALID_HANDLE_VALUE)
    {
        return false;
    }

    DWORD dwOriginalOutMode = 0;
    DWORD dwOriginalInMode = 0;
    if (!GetConsoleMode(hOut, &dwOriginalOutMode))
    {
        return false;
    }
    if (!GetConsoleMode(hIn, &dwOriginalInMode))
    {
        return false;
    }

    DWORD dwRequestedOutModes = ENABLE_VIRTUAL_TERMINAL_PROCESSING | DISABLE_NEWLINE_AUTO_RETURN;
    DWORD dwRequestedInModes = ENABLE_VIRTUAL_TERMINAL_INPUT;

    DWORD dwOutMode = dwOriginalOutMode | dwRequestedOutModes;
    if (!SetConsoleMode(hOut, dwOutMode))
    {
        // we failed to set both modes, try to step down mode gracefully.
        dwRequestedOutModes = ENABLE_VIRTUAL_TERMINAL_PROCESSING;
        dwOutMode = dwOriginalOutMode | dwRequestedOutModes;
        if (!SetConsoleMode(hOut, dwOutMode))
        {
            // Failed to set any VT mode, can't do anything here.
            return -1;
        }
    }

    DWORD dwInMode = dwOriginalInMode | ENABLE_VIRTUAL_TERMINAL_INPUT;
    if (!SetConsoleMode(hIn, dwInMode))
    {
        // Failed to set VT input mode, can't do anything here.
        return -1;
    }
#endif
    return 0;
}