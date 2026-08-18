"""Package execution entry point: ``python -m cli`` / ``python -m memdiver.cli``.

When ``cli`` was a single module, ``python -m cli`` ran it directly. Now that
it is a package (P3.1 split), Python needs an explicit ``__main__`` to execute.
:func:`main` calls ``sys.exit`` on every path, so we simply invoke it.
"""

from .main import main

if __name__ == "__main__":
    main()
