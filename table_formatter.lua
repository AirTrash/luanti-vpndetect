local function format_table(data, separator)
    -- Определяем максимальную ширину для каждого столбца
    local column_widths = {}
    for _, row in ipairs(data) do
        for col_idx, value in ipairs(row) do
            local current_width = string.len(tostring(value))
            if not column_widths[col_idx] or current_width > column_widths[col_idx] then
                column_widths[col_idx] = current_width
            end
        end
    end

    
    -- Создаем отформатированные строки
    local formatted_rows = {}
    for _, row in ipairs(data) do
        local formatted_cells = {}
        for col_idx, value in ipairs(row) do
            local padded_value = tostring(value) .. string.rep(' ', column_widths[col_idx] - string.len(tostring(value)))
            table.insert(formatted_cells, padded_value)
        end
        table.insert(formatted_rows, table.concat(formatted_cells, separator))
    end
    
    return table.concat(formatted_rows, '\n')
end


return format_table