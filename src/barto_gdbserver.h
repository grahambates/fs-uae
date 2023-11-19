#pragma once

namespace barto_gdbserver {
	bool init();
	void close();
	void vsync();
	void vsync_pre();
	void vsync_post();
	bool debug();
	bool remote_debug_copper(uaecptr addr, uae_u16 word1, uae_u16 word2, int hpos, int vpos);
	void set_exception(int n);
}
