FROM python:3.11-slim

WORKDIR /app

# Install system dependencies required for psycopg2, shapely, PostGIS, and
# ffmpeg (used by recordings.py::_try_build_playable_recording to remux a
# completed recording's chunks into one playable file via stream copy --
# never a re-encode, never a raw byte-concatenation of the MP4s -- and by
# recordings.py::_burn_watermark_best_effort, which DOES re-encode each
# chunk's video stream, since burning a GPS/timestamp overlay into the
# actual frames is unavoidably a pixel-level change). fonts-dejavu-core
# provides a real, always-present font file for ffmpeg's drawtext filter --
# a minimal Debian image has no default font otherwise.
RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    libgeos-dev \
    python3-dev \
    ffmpeg \
    fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["sh", "-c", "alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload"]
