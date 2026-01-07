// lib/motion.tsx
// Wrapper utilities for framer-motion to fix TypeScript className issues
'use client'

import React from 'react'
import { motion } from 'framer-motion'

// Utility to wrap motion components to add className as a prop (and spread it properly)
function createMotionWithClass<T extends keyof typeof motion>(component: T) {
    const MotionComponent = motion[component]

    return React.forwardRef(function MotionWithClass(props: any, ref: any) {
        const { className, ...rest } = props
        return <MotionComponent ref={ref} {...rest} {...(className ? { className } : {})} />
    })
}

// Pre-wrapped motion components for common elements
export const MotionDiv = createMotionWithClass('div')
export const MotionSpan = createMotionWithClass('span')
export const MotionButton = createMotionWithClass('button')
export const MotionInput = createMotionWithClass('input')
export const MotionP = createMotionWithClass('p')
export const MotionHeader = createMotionWithClass('header')
export const MotionSection = createMotionWithClass('section')
export const MotionArticle = createMotionWithClass('article')

// Export the utility for custom components
export { createMotionWithClass }
