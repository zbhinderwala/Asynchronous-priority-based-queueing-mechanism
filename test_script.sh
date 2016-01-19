# Files a b c d in in1 out out1 out2 out3 out4 needs to be present
./produce_job -C -c -P 1 data/a data/b &
./produce_job -C -t -P 3 data/in data/in data/out &
./produce_job -C -e -p qwerryyu -P 1 data/in data/out1 &
./produce_job -C -e -p qwerryyu -P 2 data/in1 data/out2 &
./produce_job -C -c -P 1 data/a data/b &
./produce_job -C -t -P 1 data/in data/in data/out &
./produce_job -C -t -P 3 data/in data/in data/out &
./produce_job -C -d -p qwerryyu -P 1 data/out1 data/out3 &
./produce_job -C -d -p qwerryyu -P 2 data/out2 data/out4 &
./produce_job -C -s -P 2 data/a data/c &
./produce_job -C -m -P 1 data/c data/d &
./produce_job -C -c -P 1 data/a data/b &
./produce_job -C -t -P 3 data/in data/in data/out &
./produce_job -C -t -P 3 data/in data/in data/out &
./produce_job -C -d -p qwerryyu -P 1 data/out1 data/out3 &
./produce_job -C -d -p qwerryyu -P 2 data/out2 data/out4 &
./produce_job -C -s -P 2 data/a data/c &
./produce_job -C -m -P 1 data/c data/d
