import { useState, useEffect } from 'react'
import { useQueryClient } from '@tanstack/react-query'

/**
 * 页面可见性钩子
 * - hidden：页面是否隐藏（最小化 / 切到其他标签页）
 * - 页面从隐藏变为可见时，自动触发 queryClient.invalidateQueries() 刷新当前活跃查询
 * - 用法：
 *   const { hidden } = useVisibility()
 *   useQuery({
 *     queryKey: ['recentLogs'],
 *     queryFn: getLogs,
 *     refetchInterval: hidden ? false : 5000,
 *   })
 */
export function useVisibility() {
  const [hidden, setHidden] = useState(() => (typeof document !== 'undefined' ? document.hidden : false))
  const queryClient = useQueryClient()

  useEffect(() => {
    const handle = () => {
      const isHidden = document.hidden
      setHidden(isHidden)
      if (!isHidden) {
        // 重新可见时立即唤醒并刷新活跃查询，无需修改 queryKey 污染缓存
        queryClient.invalidateQueries()
      }
    }
    document.addEventListener('visibilitychange', handle)
    return () => document.removeEventListener('visibilitychange', handle)
  }, [queryClient])

  return { hidden }
}
