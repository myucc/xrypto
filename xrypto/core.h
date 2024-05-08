#pragma once
#include <windows.h>
#include "imgui/imgui.h"
#include "imgui/imgui_impl_win32.h"
#include "imgui/imgui_impl_dx11.h"
#include "imgui/imgui_internal.h"

namespace core
{
	inline ImVec2 g_size{ 600,240 };
	inline HWND g_hwnd{ nullptr };
	inline bool g_done{ true };

	void MainCore();
}