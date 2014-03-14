function get_regions(space_a, space_s, list)
	local regions=""
	local last_reg=0
	local begin_range=0
	for v in box.space[tonumber(space_a)].index[0]:iterator(box.index.GT, list, 0) do
		if( v[0] ~= list ) then
			break
		end
		if last_reg ~= box.unpack('i', v[1]) then
			if last_reg+1 < box.unpack('i', v[1]) then
				if last_reg > 0 then
					if begin_range ~= last_reg then
						regions = regions .. "-" .. last_reg .. "," .. box.unpack('i', v[1])
					else
						regions = regions .. "," .. box.unpack('i', v[1])
					end
				else
					regions = box.unpack('i', v[1])
				end
				begin_range = box.unpack('i', v[1]);
			end
			last_reg = box.unpack('i', v[1])
		end
	end
	if last_reg > 0 and last_reg > begin_range then
		regions = regions .. "-" .. last_reg
	end
	regions = regions .. ";"
	last_reg=0
	begin_range=0
	for v in box.space[tonumber(space_s)].index[0]:iterator(box.index.GT, list, 0) do
		if( v[0] ~= list ) then
			break
		end
		if last_reg ~= box.unpack('i', v[1]) then
			if last_reg+1 < box.unpack('i', v[1]) then
				if last_reg > 0 then
					if begin_range ~= last_reg then
						regions = regions .. "-" .. last_reg .. "," .. box.unpack('i', v[1])
					else
						regions = regions .. "," .. box.unpack('i', v[1])
					end
				else
					regions = regions .. box.unpack('i', v[1])
				end
				begin_range = box.unpack('i', v[1]);
			end
			last_reg = box.unpack('i', v[1])
		end
	end
	if last_reg > 0 then
		regions = regions .. "-" .. last_reg
	end
	return regions
end

function add_chunks_s(space_num, json)
	local space = tonumber(space_num)
	local ret = 0
	for k, rec in pairs(box.cjson.decode(json)) do
		print(rec.list, tonumber(rec.chunknum), tonumber(rec.chunk.add_chunknum), tonumber(rec.chunk.host), rec.chunk.prefix)
		if not box.select(space, 0, rec.list, tonumber(rec.chunknum), tonumber(rec.chunk.add_chunknum), tonumber(rec.chunk.host), rec.chunk.prefix) then
			box.insert(space, rec.list, tonumber(rec.chunknum), tonumber(rec.chunk.add_chunknum), tonumber(rec.chunk.host), rec.chunk.prefix)
			ret=ret+1
		end
		print( "OK" )
	end
	return ret
end

function add_chunks_a(space_num, json)
	local space = tonumber(space_num)
	local ret = 0
	for k,rec in pairs(box.cjson.decode(json)) do
		if not box.select(space, 0, rec.list, tonumber(rec.chunknum), tonumber(rec.chunk.host), rec.chunk.prefix) then
			box.insert(space, rec.list, tonumber(rec.chunknum), tonumber(rec.chunk.host), rec.chunk.prefix)
			ret=ret+1
		end
	end
	return ret
end
