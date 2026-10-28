"""Start the dashboard on a THROWAWAY scan database, click through it with Edge (playwright) and save screenshots
to report/screenshots/. Never touches data/scans.db. Run from the project root:  python tests/take_screenshots.py
Needs:  pip install playwright   (uses the installed Microsoft Edge, no browser download)"""
import os
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "report" / "screenshots"
OUT.mkdir(parents=True, exist_ok=True)
PORT = 8610
URL = f"http://localhost:{PORT}"
SAMPLE = r"C:\Windows\System32\notepad.exe"  # benign Windows file used for the real-file scan screenshot

env = dict(os.environ, STATICSCAN_DB=str(Path(tempfile.mkdtemp()) / "scans.db"))
srv = subprocess.Popen([sys.executable, "-m", "streamlit", "run", "src/app.py", "--server.headless", "true",
                        "--server.port", str(PORT)], cwd=ROOT, env=env,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
try:
    for _ in range(60):
        try:
            urllib.request.urlopen(f"{URL}/_stcore/health", timeout=2)
            break
        except Exception:
            time.sleep(1)
    with sync_playwright() as p:
        browser = p.chromium.launch(channel="msedge", headless=True)

        def open_page(path, title_text, height):
            page = browser.new_page(viewport={"width": 1440, "height": height})
            page.goto(f"{URL}/{path}")
            page.wait_for_selector(f"text={title_text}", timeout=90000)
            return page

        def shot(page, name):
            page.wait_for_timeout(2500)  # let charts finish drawing
            page.screenshot(path=str(OUT / f"{name}.png"))
            print("saved", name, flush=True)

        pg = open_page("", "Malware Intelligence Center", 1000)
        shot(pg, "01_overview_empty")
        pg.get_by_role("button", name="Scan the 5 demo files").click()
        pg.wait_for_selector("text=Last analysis: 2")  # caption shows a timestamp once scans exist
        shot(pg, "02_overview_with_scans")
        pg.close()

        pg = open_page("scan_file", "Scan File", 2200)
        pg.get_by_text("Upload executable (approximate)").click()
        pg.locator('input[type="file"]').set_input_files(SAMPLE)
        pg.get_by_role("button", name="Extract static features").click()
        pg.wait_for_selector("text=Features extracted", timeout=60000)
        pg.get_by_role("button", name="Analyze with").click()
        pg.wait_for_selector("text=Analysis complete", timeout=60000)
        pg.wait_for_selector("text=PE file information")
        shot(pg, "03_scan_real_file_report")
        pg.close()

        pg = open_page("scan_file", "Scan File", 1500)  # a scan the dashboard calls Uncertain (models disagree)
        pg.get_by_text("By index").click()
        pg.get_by_label("Test row index").fill("29")
        pg.get_by_label("Test row index").press("Enter")
        pg.get_by_role("button", name="Analyze with").click()
        pg.wait_for_selector("text=Treat this as unknown", timeout=60000)
        shot(pg, "03b_uncertain_report")
        pg.close()

        pg = open_page("history", "Scan History", 1000)
        shot(pg, "04_scan_history")
        pg.close()
        pg = open_page("performance", "Model Performance", 3400)
        shot(pg, "05_model_performance")
        pg.close()
        pg = open_page("dataset", "Dataset Explorer", 2300)
        shot(pg, "06_dataset_explorer")
        pg.close()
        pg = open_page("about", "About Project", 1300)
        shot(pg, "07_about")
        browser.close()
finally:
    srv.terminate()
