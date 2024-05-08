#include "core.h"
#include "features.hpp"

void Interface2()
{

}

void Interface1()
{
	ImGui::PushItemWidth(270);
	ImGui::SetCursorPos(ImVec2(10, 30));
	ImGui::InputText("##key", data::keyU, sizeof(data::keyU), data::is_hidden ? ImGuiInputTextFlags_Password + 512 : 512,
		[](ImGuiInputTextCallbackData* data) -> int {if (data->EventChar == 32) { return 1; } return 0; });
	ImGui::PopItemWidth();

	ImGui::PushItemWidth(90);
	ImGui::SetCursorPos(ImVec2(290, 30));
	ImGui::Combo("##combo", &data::curr_item, data::items, IM_ARRAYSIZE(data::items));
	ImGui::PopItemWidth();

	ImGui::SetCursorPos(ImVec2(390, 30));
	ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.24, 0.29, 0.61, 1.0));
	if (ImGui::Button("hidekey", ImVec2{ 60, 20 })) data::is_hidden = !data::is_hidden;
	ImGui::PopStyleColor();

	ImGui::SetCursorPos(ImVec2(460, 30));
	ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.55, 0.70, 0.72, 1.0));
	if (ImGui::Button("cleanup", ImVec2{ 60,20 })) clean_up();
	ImGui::PopStyleColor();

	ImGui::SetCursorPos(ImVec2(10, 60));
	ImGui::InputTextMultiline("##in", data::inputU, sizeof(data::inputU), ImVec2(370, 80));

	ImGui::SetCursorPos(ImVec2(10, 150));
	ImGui::InputTextMultiline("##out", data::outputU, sizeof(data::outputU), ImVec2(370, 80));

	ImGui::SetCursorPos(ImVec2(390, 60));
	if (ImGui::Button("text-enc", ImVec2{ 60,20 })) text_ed(TRUE);

	ImGui::SetCursorPos(ImVec2(460, 60));
	if (ImGui::Button("text-dec", ImVec2{ 60,20 })) text_ed(FALSE);

	ImGui::SetCursorPos(ImVec2(530, 60));
	if (ImGui::Button("pickfile", ImVec2{ 60,20 })) pick_file();

	ImGui::SetCursorPos(ImVec2(390, 90));
	if (ImGui::Button("file-enc", ImVec2{ 60,20 })) crypt_file(data::file_path, TRUE);

	ImGui::SetCursorPos(ImVec2(460, 90));
	if (ImGui::Button("file-dec", ImVec2{ 60,20 })) crypt_file(data::file_path, FALSE);

	ImGui::SetCursorPos(ImVec2(530, 90));
	if (ImGui::Button("pickdir", ImVec2{ 60,20 })) pick_fold();

	ImGui::SetCursorPos(ImVec2(390, 120));
	if (ImGui::Button("split-f", ImVec2{ 60,20 })) split_f();

	ImGui::SetCursorPos(ImVec2(460, 120));
	if (ImGui::Button("merge-f", ImVec2{ 60,20 })) merge_f();

	ImGui::SetCursorPos(ImVec2(530, 120));
	if (ImGui::Button("hash-f", ImVec2{ 60,20 })) hash_f();

	ImGui::SetCursorPos(ImVec2(390, 150));
	if (ImGui::Button("erase-d", ImVec2{ 60,20 })) erase_dir();

	ImGui::SetCursorPos(ImVec2(460, 150));
	if (ImGui::Button("line-enc", ImVec2{ 60,20 })) eline_ed(TRUE);

	ImGui::SetCursorPos(ImVec2(530, 150));
	if (ImGui::Button("line-dec", ImVec2{ 60,20 })) eline_ed(FALSE);

	ImGui::SetCursorPos(ImVec2(390, 180));
	if (ImGui::Button("dir-enc", ImVec2{ 60,20 })) dir_ed(TRUE);

	ImGui::SetCursorPos(ImVec2(460, 180));
	if (ImGui::Button("dir-dec", ImVec2{ 60,20 })) dir_ed(FALSE);

	ImGui::PushItemWidth(200);
	ImGui::SetCursorPos(ImVec2(390, 210));
	ImGui::SliderInt("##splitsl", &data::split_num, 2, 255);
	ImGui::PopItemWidth();
}

void core::MainCore()
{
	ImGui::SetNextWindowPos({ 0, 0 }, ImGuiCond_FirstUseEver);
	ImGui::SetNextWindowSize(ImVec2(core::g_size.x, core::g_size.y));
	ImGui::Begin("<nyu>", &core::g_done, 256 | 32 | 4 | 2);

	ImGui::SetCursorPos(ImVec2(core::g_size.x - 70, 30));
	ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.50, 0.20, 0.86, 1.0f));
	if (ImGui::Button("switch", ImVec2{ 60,20 })) data::ctab = (data::ctab % 2) + 1;
	ImGui::PopStyleColor();

	switch (data::ctab) {
	case 1:Interface1(); break;
	case 2:Interface2(); break;
	}

	ImGui::End();
}