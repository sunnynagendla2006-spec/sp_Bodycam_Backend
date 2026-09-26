FROM python:3.11-slim

WORKDIR /app

# Install system dependencies required for ffmpeg (used by
# recordings.py::_try_build_playable_recording to remux a completed
# recording's chunks into one playable file via stream copy -- never a
# re-encode, never a raw byte-concatenation of the MP4s -- and by
# recordings.py::_burn_watermark_best_effort, which DOES re-encode each
# chunk's video stream, since burning a GPS/timestamp overlay into the
# actual frames is unavoidably a pixel-level change). fonts-dejavu-core
# provides a real, always-present font file for ffmpeg's drawtext filter --
# a minimal Debian image has no default font otherwise.
RUN apt-get update && apt-get install -y \
    build-essential \
    python3-dev \
    ffmpeg \
    fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

# No migration step: MongoDB/Beanie collections and indexes are created
# idempotently at application startup (see app/database.py::init_db).
#
# --reload is dev-only (extra file-watcher process, blocks multi-worker
# use) -- PORT is read from the environment because most PaaS hosts
# (Render included) assign it dynamically rather than always using 8000.
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
