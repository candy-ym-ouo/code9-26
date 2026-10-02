-- 安全修复：画册只能收录本资料库的灵感。
-- 历史上 addItem 未校验灵感归属，可能把其他资料库的灵感卡写入 album_item，
-- 进而通过画册详情、封面、缺口统计与已发布快照对外暴露外部库内容。
-- 本迁移清理已污染的越权入册关系，并同步净化历史快照。

-- 1) 删除跨库的入册关系（album_gap / album_item 随 album 外键无关联到 inspiration，
--    需手动按 album 归属库与灵感归属库比对）。
DELETE FROM album_item
WHERE id IN (
  SELECT ai.id
  FROM album_item ai
  JOIN album al ON al.id = ai.album_id
  JOIN inspiration i ON i.id = ai.inspiration_id
  WHERE al.library_id <> i.library_id
);

-- 2) 净化已发布快照：移除其中引用跨库灵感的条目（json_each 需 SQLite JSON1）。
DELETE FROM album_snapshot
WHERE id IN (
  SELECT s.id
  FROM album_snapshot s
  JOIN album al ON al.id = s.album_id
  JOIN json_each(s.payload, '$.items') je
  LEFT JOIN inspiration i ON i.id = json_extract(je.value, '$.inspirationId')
  WHERE i.id IS NULL OR i.library_id <> al.library_id
);
