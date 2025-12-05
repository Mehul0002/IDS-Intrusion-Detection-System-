"""
Main entry point for the IDS Mini application.
"""

import tkinter as tk
from gui import IDS_GUI

def main():
    """
    Initialize and run the IDS GUI application.
    """
    root = tk.Tk()
    app = IDS_GUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
