"""Check the shell command helpers the phone tools build their commands with."""

import pathlib
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
ANDROID = ROOT / "main/android"

MAIN = r'''
#include <cassert>
#include <cstdio>
#include <fstream>
#include <string>
#include <vector>

#include "adb_shell.h"

int main(int argc, char** argv) {
    assert(adb_shell::Service("wm size") == "exec:wm size");

    // Spaces become %s and everything else stays inside the quotes, so the
    // device shell cannot split or expand a model supplied string.
    assert(adb_shell::QuoteText("hello") == "'hello'");
    assert(adb_shell::QuoteText("hello world") == "'hello%sworld'");
    assert(adb_shell::QuoteText("it's") == "'it'\\''s'");
    assert(adb_shell::QuoteText("a; rm -rf /") == "'a;%srm%s-rf%s/'");
    assert(adb_shell::TextCommand("hi") == "input text 'hi'");

    assert(adb_shell::IsTypeable("abc 123"));
    assert(!adb_shell::IsTypeable(""));
    assert(!adb_shell::IsTypeable("\xe4\xb8\xad\xe6\x96\x87"));
    assert(!adb_shell::IsTypeable("line\nbreak"));

    // Unicode text goes through the ADBKeyboard broadcast instead.
    assert(adb_shell::IsBroadcastable("\xe4\xb8\xad\xe6\x96\x87"));
    assert(adb_shell::IsBroadcastable("a b"));
    assert(!adb_shell::IsBroadcastable(""));
    assert(!adb_shell::IsBroadcastable("a\nb"));
    assert(!adb_shell::IsBroadcastable("a\x01b"));
    assert(adb_shell::BroadcastTextCommand("hi") ==
           "am broadcast -a ADB_INPUT_TEXT --es msg 'hi'");
    assert(adb_shell::BroadcastTextCommand("\xe4\xb8\xad\xe6\x96\x87") ==
           "am broadcast -a ADB_INPUT_TEXT --es msg '\xe4\xb8\xad\xe6\x96\x87'");
    assert(adb_shell::BroadcastTextCommand("it's") ==
           "am broadcast -a ADB_INPUT_TEXT --es msg 'it'\\''s'");

    assert(adb_shell::KeyCode("back") != nullptr && *adb_shell::KeyCode("back") == 4);
    assert(adb_shell::KeyCode("enter") != nullptr && *adb_shell::KeyCode("enter") == 66);
    assert(adb_shell::KeyCode("nope") == nullptr);
    assert(adb_shell::KeyCommand(4) == "input keyevent 4");

    // Launch resolves the launcher activity through monkey; the fallback takes
    // the component from the last line of resolve-activity --brief.
    assert(adb_shell::LaunchCommand("com.android.chrome") ==
           "monkey -p com.android.chrome -c android.intent.category.LAUNCHER 1");
    assert(adb_shell::LastNonEmptyLine(
               "\n  priority=0 preferredOrder=0\n  com.android.chrome/com.android.chrome.Main\n") ==
           "com.android.chrome/com.android.chrome.Main");
    assert(adb_shell::LastNonEmptyLine("") == "");
    assert(adb_shell::LastNonEmptyLine("  \n\t\n") == "");

    int width = 0;
    int height = 0;
    assert(adb_shell::ParseScreenSize("Physical size: 1080x2400\n", &width, &height));
    assert(width == 1080 && height == 2400);
    // A resolution override wins over the physical size.
    assert(adb_shell::ParseScreenSize(
        "Physical size: 1080x2400\nOverride size: 720x1600\n", &width, &height));
    assert(width == 720 && height == 1600);
    assert(!adb_shell::ParseScreenSize("error: no display\n", &width, &height));

    // The focused window names the app on screen, which is what the privacy
    // gate reads before a screenshot or a tap.
    assert(adb_shell::ParseFocusPackage(
               "  mCurrentFocus=Window{2f6c1a3 u0 "
               "com.android.chrome/com.google.android.apps.chrome.Main}\n") ==
           "com.android.chrome");
    // Older ROMs only print mFocusedApp.
    assert(adb_shell::ParseFocusPackage(
               "  mFocusedApp=ActivityRecord{abc123 u0 com.android.settings/.Settings t42}\n") ==
           "com.android.settings");
    assert(adb_shell::ParseFocusPackage("  mCurrentFocus=null\n").empty());
    assert(adb_shell::ParseFocusPackage("ERROR: no window manager\n").empty());
    assert(adb_shell::ParseFocusPackage("").empty());

    // A hidden stale window listed above the focused one must not win:
    // mCurrentFocus says what is on screen now.
    assert(adb_shell::ParseFocusPackage(
               "  Window #3 Window{abc u0 com.miui.gallery/FakeGallery}\n"
               "  mCurrentFocus=Window{2f6c1a3 u0 "
               "com.android.chrome/com.google.android.apps.chrome.Main}\n") ==
           "com.android.chrome");

    // Real output from a Xiaomi Pad 5 on its home screen: MIUI prints no
    // mCurrentFocus there at all, the launcher window is the only usable
    // source. See scripts/tests/data/desktop_dump.txt.
    if (argc > 1) {
        std::ifstream file(argv[1]);
        std::string dump((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        assert(!dump.empty());
        assert(adb_shell::ParseFocusPackage(dump) == "com.miui.home");
    }

    // Money, messages, photos, secrets and the system UI (lock screen and
    // notification previews) are off limits; everything else is unknown.
    assert(adb_shell::IsSensitivePackage("com.google.android.apps.messaging"));
    assert(adb_shell::IsSensitivePackage("com.android.mms"));
    assert(adb_shell::IsSensitivePackage("com.miui.gallery"));
    assert(adb_shell::IsSensitivePackage("com.google.android.apps.photos"));
    // systemui is the launcher itself, so it must stay allowed: blocking it
    // made every desktop look fail.
    assert(!adb_shell::IsSensitivePackage("com.android.systemui"));
    assert(adb_shell::IsSensitivePackage("com.bankofamerica.cashpro"));
    assert(adb_shell::IsSensitivePackage("com.samsung.android.spay"));
    // Brokers and crypto exchanges.
    assert(adb_shell::IsSensitivePackage("com.hexin.plat.android"));       // 同花顺
    assert(adb_shell::IsSensitivePackage("com.eastmoney.android.berlin")); // 东方财富
    assert(adb_shell::IsSensitivePackage("com.futunn.FutuNT"));            // 富途
    assert(adb_shell::IsSensitivePackage("com.robinhood.android"));
    assert(adb_shell::IsSensitivePackage("com.traderepublic.app"));
    assert(adb_shell::IsSensitivePackage("com.binance.dev"));
    assert(adb_shell::IsSensitivePackage("com.okinc.okex"));
    assert(adb_shell::IsSensitivePackage("com.coinbase.android"));
    assert(!adb_shell::IsSensitivePackage("com.android.chrome"));
    assert(!adb_shell::IsSensitivePackage("com.android.settings"));
    assert(!adb_shell::IsSensitivePackage("com.tencent.mm"));
    assert(!adb_shell::IsSensitivePackage(""));

    // The user's own block list is a comma separated string in NVS.
    assert(!adb_shell::IsPackageName("com"));
    assert(!adb_shell::IsPackageName(".com.example"));
    assert(!adb_shell::IsPackageName("com..example"));
    assert(!adb_shell::IsPackageName("com.example.App"));
    assert(!adb_shell::IsPackageName("nodot"));
    assert(!adb_shell::IsPackageName(""));
    assert(adb_shell::IsPackageName("com.example.app"));

    std::string list;
    list = adb_shell::ListAdd(list, "com.example.app");
    assert(list == "com.example.app");
    // Adding twice is a no-op, and so is anything that is not a package.
    assert(adb_shell::ListAdd(list, "com.example.app") == list);
    assert(adb_shell::ListAdd(list, "not a package") == list);
    list = adb_shell::ListAdd(list, "com.other.app");
    assert(list == "com.example.app,com.other.app");
    assert(adb_shell::ListContains(list, "com.other.app"));
    assert(!adb_shell::ListContains(list, "com.exam"));
    assert(adb_shell::ListRemove(list, "com.example.app") == "com.other.app");
    assert(adb_shell::ListRemove(list, "com.missing.app") == list);
    assert(adb_shell::ListRemove("com.other.app", "com.other.app").empty());

    // The control tree replaces the screenshot: whatever the model acts on has
    // to come out of this text intact, including Chinese labels.
    assert(adb_shell::UiDumpCommand().find("uiautomator dump") != std::string::npos);
    assert(adb_shell::UnescapeXml("Tom &amp; Jerry") == "Tom & Jerry");
    assert(adb_shell::UnescapeXml("&quot;x&quot;") == "\"x\"");
    assert(adb_shell::UnescapeXml("&lt;a&gt;") == "<a>");
    assert(adb_shell::UnescapeXml("it&apos;s") == "it's");
    assert(adb_shell::UnescapeXml("nothing") == "nothing");

    const std::string xml =
        "<?xml version='1.0' encoding='UTF-8' standalone='yes' ?><hierarchy rotation=\"0\">"
        "<node index=\"0\" text=\"\" class=\"android.widget.FrameLayout\" clickable=\"false\""
        " focused=\"false\" bounds=\"[0,0][1080,2400]\">"
        "<node index=\"1\" text=\"\xe5\xbe\xae\xe4\xbf\xa1\" class=\"android.widget.TextView\""
        " clickable=\"false\" focused=\"false\" bounds=\"[60,1750][330,1900]\" />"
        "<node index=\"2\" text=\"\" content-desc=\"\xe6\x90\x9c\xe7\xb4\xa2\""
        " class=\"android.widget.ImageButton\" clickable=\"true\" bounds=\"[40,120][1040,260]\" />"
        "<node index=\"3\" text=\"Tom &amp; Jerry\" class=\"android.widget.TextView\""
        " clickable=\"false\" bounds=\"[10,300][200,350]\" />"
        "<node index=\"4\" text=\"\" class=\"android.widget.EditText\" clickable=\"true\""
        " focused=\"true\" bounds=\"[300,300][500,400]\" />"
        "<node index=\"5\" text=\"\" class=\"android.widget.TextView\" clickable=\"false\""
        " focused=\"false\" bounds=\"[0,0][10,10]\" />"
        "<node index=\"6\" text=\"\" class=\"android.view.View\" clickable=\"true\""
        " bounds=\"[5,5][6,6]\" />"
        "</node></hierarchy>";

    auto nodes = adb_shell::ParseUiNodes(xml);
    // The empty container and the unlabelled, unclickable view are gone.
    assert(nodes.size() == 5);
    assert(nodes[0].label == "\xe5\xbe\xae\xe4\xbf\xa1");
    assert(nodes[0].class_name == "TextView");
    assert(nodes[0].x1 == 60 && nodes[0].y1 == 1750 && nodes[0].x2 == 330 && nodes[0].y2 == 1900);
    assert(!nodes[0].focused);
    // content-desc stands in for a missing text, which is how icon buttons read.
    assert(nodes[1].label == "\xe6\x90\x9c\xe7\xb4\xa2");
    assert(nodes[1].class_name == "ImageButton");
    assert(nodes[2].label == "Tom & Jerry");
    assert(nodes[3].focused && nodes[3].class_name == "EditText");
    assert(nodes[4].class_name == "View");
    assert(adb_shell::ParseUiNodes("garbage").empty());
    assert(adb_shell::ParseUiNodes("").empty());

    const std::string formatted =
        adb_shell::FormatUiNodes(nodes, 1080, 2400, "com.tencent.mm", 40);
    assert(formatted.find("Screen 1080x2400 app com.tencent.mm, 5 controls") == 0);
    assert(formatted.find("1 TextView \"\xe5\xbe\xae\xe4\xbf\xa1\" [60,1750][330,1900]") !=
           std::string::npos);
    assert(formatted.find("4 EditText") != std::string::npos);
    assert(formatted.find("focused") != std::string::npos);

    // Past the line cap the rest is only counted, so a long list cannot flood
    // the model.
    const std::string capped = adb_shell::FormatUiNodes(nodes, 1080, 2400, "", 2);
    assert(capped.find("... and 3 more") != std::string::npos);
    assert(capped.find("EditText") == std::string::npos);

    // A quoted label would break the line format, so quotes become spaces.
    adb_shell::UiNode quoted;
    quoted.label = "say \"hi\"";
    quoted.x2 = 10;
    quoted.y2 = 10;
    const std::string one = adb_shell::FormatUiNodes({quoted}, 100, 100, "", 40);
    assert(one.find("\"say  hi \"") != std::string::npos);

    // Truncation has to stop on a character boundary or the JSON sent to the
    // server is invalid UTF-8.
    std::string cut = "\xe4\xb8\xad\xe6\x96\x87";
    adb_shell::TruncateUtf8(&cut, 5);
    assert(cut == "\xe4\xb8\xad");
    cut = "\xe4\xb8\xad\xe6\x96\x87";
    adb_shell::TruncateUtf8(&cut, 3);
    assert(cut == "\xe4\xb8\xad");
    cut = "abc";
    adb_shell::TruncateUtf8(&cut, 10);
    assert(cut == "abc");
    cut = "a\xe4\xb8\xad";
    adb_shell::TruncateUtf8(&cut, 2);
    assert(cut == "a");

    // Batch steps: one line each, parsed before anything touches the phone.
    std::vector<adb_shell::BatchStep> steps;
    std::string batch_error;
    assert(adb_shell::ParseBatchSteps(
        "tap 3\n"
        "tap 500 800\n"
        "type hello world\n"
        "key back\n"
        "swipe 100 200 300 400 300\n"
        "launch com.android.chrome\n"
        "wait 1500\n",
        &steps, &batch_error));
    assert(batch_error.empty());
    assert(steps.size() == 7);
    assert(steps[0].op == adb_shell::BatchStep::Op::kTapIndex && steps[0].index == 3);
    assert(steps[1].op == adb_shell::BatchStep::Op::kTapXY && steps[1].x == 500 &&
           steps[1].y == 800);
    assert(steps[2].op == adb_shell::BatchStep::Op::kType && steps[2].text == "hello world");
    assert(steps[3].op == adb_shell::BatchStep::Op::kKey && steps[3].key_code == 4);
    assert(steps[4].op == adb_shell::BatchStep::Op::kSwipe && steps[4].x == 100 &&
           steps[4].y2 == 400 && steps[4].duration_ms == 300);
    assert(steps[5].op == adb_shell::BatchStep::Op::kLaunch &&
           steps[5].text == "com.android.chrome");
    assert(steps[6].op == adb_shell::BatchStep::Op::kWait && steps[6].duration_ms == 1500);
    // Empty lines are skipped, surrounding whitespace is trimmed.
    assert(adb_shell::ParseBatchSteps("\n  tap 1  \n\n", &steps, &batch_error) &&
           steps.size() == 1 && steps[0].index == 1);
    // Chinese text is a valid type step now.
    assert(adb_shell::ParseBatchSteps("type \xe6\x88\x91\xe7\x9a\x84\xe6\xa2\xa6\xe6\x83\xb3",
                                      &steps, &batch_error) &&
           steps.size() == 1 && steps[0].op == adb_shell::BatchStep::Op::kType &&
           steps[0].text == "\xe6\x88\x91\xe7\x9a\x84\xe6\xa2\xa6\xe6\x83\xb3");

    // Every malformed line aborts with its line number.
    struct {
        const char* spec;
        const char* line;  // "0" = reported line number is not pinned
    } bad[] = {
        {"", "0"},
        {"tap", "1"},
        {"tap 0", "1"},
        {"tap 1001", "1"},
        {"tap 1001 10", "1"},
        {"tap -1", "1"},
        {"tap 1 2 3", "1"},
        {"type", "1"},
        {"type a\x01b", "1"},
        {"type line\nbreak", "2"},
        {"key nope", "1"},
        {"swipe 1 2 3 4", "1"},
        {"swipe 1 2 3 4 5", "1"},   // ms below 50
        {"swipe 1 2 3 4 5000", "1"},
        {"swipe x 2 3 4 300", "1"},
        {"launch nodot", "1"},
        {"launch com.example.app extra", "1"},
        {"wait", "1"},
        {"wait 0", "1"},
        {"wait 6000", "1"},
        {"foo 1", "1"},
        {"tap 1\nbad step", "2"},
    };
    for (const auto& case_ : bad) {
        std::string err;
        std::vector<adb_shell::BatchStep> parsed;
        assert(!adb_shell::ParseBatchSteps(case_.spec, &parsed, &err));
        assert(!err.empty());
        if (case_.line[0] != '0') {
            assert(err.find(std::string("Line ") + case_.line + ":") == 0);
        }
    }

    // Forty steps fit, forty-one do not.
    std::string forty;
    for (int i = 0; i < 40; i++) {
        forty += "wait 1\n";
    }
    assert(adb_shell::ParseBatchSteps(forty, &steps, &batch_error) && steps.size() == 40);
    assert(!adb_shell::ParseBatchSteps(forty + "wait 1\n", &steps, &batch_error));

    std::printf("android shell tests passed\n");
    return 0;
}
'''


@unittest.skipUnless(shutil.which("c++"), "requires a host C++ compiler")
class AndroidShellTest(unittest.TestCase):
    def test_helpers(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = pathlib.Path(directory) / "android-shell-test"
            build = subprocess.run(
                ["c++", "-std=c++23", "-Wall", "-Wextra", "-Werror",
                 f"-I{ANDROID}", "-x", "c++", "-", "-o", str(binary)],
                input=MAIN,
                text=True,
                capture_output=True,
            )
            self.assertEqual(build.returncode, 0, build.stderr)
            run = subprocess.run([str(binary), str(ROOT / "scripts/tests/data/desktop_dump.txt")],
                                 capture_output=True, text=True, timeout=60)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertIn("android shell tests passed", run.stdout)


if __name__ == "__main__":
    unittest.main()
